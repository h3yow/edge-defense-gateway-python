"""来源信誉：违规累积、逐级升级、隔离与退避恢复。

等级演进（连续违规逐级升级）：
    NORMAL --1--> SUSPECT --2--> RESTRICTED --3--> QUARANTINED

隔离：
    达到升级阈值即进入隔离，隔离时长 = base * 2 ** (quarantine_count - 1)，
    第 1 次 1 个 base、第 2 次 2 个、第 3 次 4 个……（指数退避，封顶）。

恢复（隔离到期后的退避恢复）：
    QUARANTINED 到期自动降为 RESTRICTED（观察期）；
    观察期内每经过 recover_step_seconds 且无新违规则再降一级：
    RESTRICTED -> SUSPECT -> NORMAL；观察期内再违规立即重新隔离。

表现良好加速恢复：
    加速进度有两个独立来源，阈值同为 good_accel_steps（默认 2）：
    - 时间驱动：每完成一个无违规恢复步（recover_step_seconds）
      recovery_progress +1，达标时直接跳回 NORMAL（跳级兑现，进度清零）；
    - 请求驱动：隔离后观察恢复期（in_recovery 的 RESTRICTED/SUSPECT）内
      每一次被放行的请求（record_good）good_progress +1，达标时立即降
      一级（RESTRICTED->SUSPECT->NORMAL，进度归零）。
    因此观察期内持续表现良好的身份明显比“不再出现、只按时间熬”的身份
    更快脱身；未进入观察期的身份不受请求驱动加速影响（行为同旧版本）。
    观察期内一旦再违规：两项进度都清零、按连续违规计数立即回退（该隔离
    就隔离）。进度随状态一起持久化，进程重启后不重攒、不白攒；读路径
    （get_level / is_blocked / snapshot）不累计进度，同一次请求不会被
    多个调用点算重。

回收与保留（防止长期运行状态无限膨胀）：
    - 等级为 NORMAL 且超过 gc_idle_seconds 未出现的身份会被真正回收：从活动
      状态表中删除，只把影响后续结论的最小信息（quarantine_count、last_seen）
      移入独立的归档表；再次出现时从归档表原地复活，结论与回收前完全一致
      （不会退化成“从没见过”）。
    - 归档表本身有界：记录超过 gc_archive_seconds（默认 7 天）未再出现即彻底
      过期，且条数超过 gc_archive_max_entries 时淘汰最旧——活动状态与归档
      记录的规模都不随见过的身份数无限增长。
    - 隔离中、观察恢复期（RESTRICTED/SUSPECT）或最近有活动的身份绝不回收。
    - 每个身份的事件流水最多保留 max_events_per_client 条（超出丢弃最旧）。
    - gc 可显式调用，也会按 gc_interval_seconds 在请求路径上自动触发。

持久化：
    状态与事件流水以 JSON 落盘，进程重启后可复现；每次状态变更都追加事件，
    形成可追溯记录。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass

from gateway.models import ReputationLevel

# 进入各等级所需的连续违规次数
_LEVEL_THRESHOLDS = (
    (3, ReputationLevel.QUARANTINED),
    (2, ReputationLevel.RESTRICTED),
    (1, ReputationLevel.SUSPECT),
)
_QUARANTINE_VIOLATIONS = 3
_BASE_QUARANTINE_SECONDS = 10.0
_MAX_QUARANTINE_SECONDS = 300.0
_RECOVER_STEP_SECONDS = 5.0
_GOOD_ACCEL_STEPS = 2
_GC_IDLE_SECONDS = 3600.0
_MAX_EVENTS_PER_CLIENT = 100
_GC_INTERVAL_SECONDS = 60.0
_GC_ARCHIVE_SECONDS = 7 * 24 * 3600.0  # 归档记录（前科结论）保留时长，默认 7 天
_GC_ARCHIVE_MAX_ENTRIES = 10000        # 归档记录条数上限，超出淘汰最旧


@dataclass
class _State:
    client_id: str
    violations: int = 0          # 当前连续违规计数（恢复成功时清零/递减）
    level: ReputationLevel = ReputationLevel.NORMAL
    quarantine_count: int = 0   # 历史进入隔离的次数（决定退避时长）
    quarantined_until: float = 0.0
    level_since: float = 0.0    # 进入当前等级的时间
    recovery_progress: int = 0  # 时间驱动的无违规恢复步数（达到阈值加速降级，违规清零）
    good_progress: int = 0      # 请求驱动的放行计数（观察期内达标立即降级，违规清零）
    in_recovery: bool = False   # 是否处于隔离后的观察恢复期（隔离到期置位，回到 NORMAL 清除）
    last_seen: float = 0.0      # 最近一次出现（请求/违规/查询）的时间
    archived: bool = False      # 兼容旧状态文件的字段；活动状态下恒为 False
                                # （回收即删除出状态表，结论移入归档表）

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "violations": self.violations,
            "level": self.level.value,
            "quarantine_count": self.quarantine_count,
            "quarantined_until": self.quarantined_until,
            "level_since": self.level_since,
            "recovery_progress": self.recovery_progress,
            "good_progress": self.good_progress,
            "in_recovery": self.in_recovery,
            "last_seen": self.last_seen,
            "archived": self.archived,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "_State":
        return cls(
            client_id=data["client_id"],
            violations=int(data["violations"]),
            level=ReputationLevel(data["level"]),
            quarantine_count=int(data["quarantine_count"]),
            quarantined_until=float(data["quarantined_until"]),
            level_since=float(data["level_since"]),
            recovery_progress=int(data.get("recovery_progress", 0)),
            good_progress=int(data.get("good_progress", 0)),
            in_recovery=bool(data.get("in_recovery", False)),
            last_seen=float(data.get("last_seen", 0.0)),
            archived=bool(data.get("archived", False)),
        )


class ReputationManager:
    def __init__(
        self,
        state_path: str | None = None,
        base_quarantine_seconds: float = _BASE_QUARANTINE_SECONDS,
        max_quarantine_seconds: float = _MAX_QUARANTINE_SECONDS,
        recover_step_seconds: float = _RECOVER_STEP_SECONDS,
        good_accel_steps: int = _GOOD_ACCEL_STEPS,
        gc_idle_seconds: float = _GC_IDLE_SECONDS,
        max_events_per_client: int = _MAX_EVENTS_PER_CLIENT,
        gc_interval_seconds: float = _GC_INTERVAL_SECONDS,
        gc_archive_seconds: float = _GC_ARCHIVE_SECONDS,
        gc_archive_max_entries: int = _GC_ARCHIVE_MAX_ENTRIES,
    ) -> None:
        if good_accel_steps < 1:
            raise ValueError("good_accel_steps must be >= 1")
        if gc_idle_seconds <= 0:
            raise ValueError("gc_idle_seconds must be > 0")
        if max_events_per_client < 1:
            raise ValueError("max_events_per_client must be >= 1")
        if gc_archive_seconds <= 0:
            raise ValueError("gc_archive_seconds must be > 0")
        if gc_archive_max_entries < 1:
            raise ValueError("gc_archive_max_entries must be >= 1")
        self.state_path = state_path
        self.base_quarantine_seconds = base_quarantine_seconds
        self.max_quarantine_seconds = max_quarantine_seconds
        self.recover_step_seconds = recover_step_seconds
        self.good_accel_steps = good_accel_steps
        self.gc_idle_seconds = gc_idle_seconds
        self.max_events_per_client = max_events_per_client
        self.gc_interval_seconds = gc_interval_seconds
        self.gc_archive_seconds = gc_archive_seconds
        self.gc_archive_max_entries = gc_archive_max_entries
        self._lock = threading.Lock()
        self._states: dict[str, _State] = {}
        # 归档表：已回收身份的结论性信息（quarantine_count 等），
        # 本身有界（按 gc_archive_seconds 过期 + 条数上限淘汰最旧），
        # 因此活动状态与归档记录的规模都不随见过的身份数无限增长。
        self._archive: dict[str, dict] = {}
        self._events: list[dict] = []
        self._last_gc: float = 0.0

    # ---- 内部：调用方需持锁，且先做时间驱动的恢复推进 ----

    def _get(self, client_id: str) -> _State:
        st = self._states.get(client_id)
        if st is None:
            st = _State(client_id=client_id)
            # 已回收身份再次出现：从归档表还原结论性字段（前科不丢），
            # 因此再次隔离的退避次数/时长与从未回收完全一致。
            archived = self._archive.pop(client_id, None)
            if archived is not None:
                st.quarantine_count = int(archived.get("quarantine_count", 0))
                st.last_seen = float(archived.get("last_seen", 0.0))
            self._states[client_id] = st
        return st

    def _touch(self, st: _State, now: float) -> None:
        """登记一次“出现”：刷新 last_seen（回收判定以此衡量闲置时长）。"""
        st.last_seen = now

    def _trim_events(self, client_id: str) -> None:
        """调用方需持锁。将该身份的事件裁剪到保留边界（丢弃最旧）。"""
        idx = [i for i, e in enumerate(self._events) if e.get("client_id") == client_id]
        overflow = len(idx) - self.max_events_per_client
        if overflow > 0:
            drop = set(idx[:overflow])
            self._events = [e for i, e in enumerate(self._events) if i not in drop]

    def _advance(self, st: _State, now: float) -> bool:
        """根据当前时间推进恢复状态机（隔离到期 -> 逐级退避恢复）。

        每次调用每级最多推进一格（level_since 随推进刷新），因此重复调用
        不会重复累计恢复进度。返回是否发生了状态迁移；调用方在迁移后落盘，
        保证恢复进度随重启完整恢复（不白攒、不重攒）。
        """
        changed = False
        if st.level is ReputationLevel.QUARANTINED:
            if now < st.quarantined_until:
                return False
            # 隔离到期：降为 RESTRICTED，开始观察期；连续违规计数保留 2
            st.level = ReputationLevel.RESTRICTED
            st.violations = 2
            st.level_since = now
            st.in_recovery = True  # 进入观察恢复期：放行请求可累计加速进度
            self._emit(st, now, "quarantine_released", "隔离到期，进入限制观察期")
            changed = True
        if st.level is ReputationLevel.RESTRICTED:
            if now - st.level_since >= self.recover_step_seconds:
                self._recover_step(st, now)
                changed = True
        if st.level is ReputationLevel.SUSPECT:
            if now - st.level_since >= self.recover_step_seconds:
                self._recover_step(st, now)
                changed = True
        return changed

    def _recover_step(self, st: _State, now: float) -> None:
        """完成一个无违规恢复步：进度 +1；达到加速阈值则直接跳回 NORMAL。"""
        st.recovery_progress += 1
        accelerated = st.recovery_progress >= self.good_accel_steps
        if st.level is ReputationLevel.RESTRICTED and not accelerated:
            st.level = ReputationLevel.SUSPECT
            st.violations = 1
            st.level_since = now
            self._emit(st, now, "recover", "观察期无违规，降为可疑")
            return
        st.level = ReputationLevel.NORMAL
        st.violations = 0
        st.level_since = now
        st.in_recovery = False  # 观察恢复期结束
        if accelerated:
            self._emit(
                st, now, "accelerated_recover",
                f"连续{st.recovery_progress}步无违规，加速恢复正常",
            )
        else:
            self._emit(st, now, "recover", "观察期无违规，恢复正常")
        st.recovery_progress = 0  # 进度已兑现，归零重新累积

    def _good_step_down(self, st: _State, now: float) -> None:
        """表现良好达标：立即降一级（RESTRICTED->SUSPECT->NORMAL），进度归零。"""
        if st.level is ReputationLevel.RESTRICTED:
            st.level = ReputationLevel.SUSPECT
            st.violations = 1
        else:
            st.level = ReputationLevel.NORMAL
            st.violations = 0
            st.in_recovery = False  # 观察恢复期结束
        st.level_since = now
        st.good_progress = 0  # 进度已兑现，归零重新累积
        self._emit(
            st, now, "accelerated_recover",
            f"观察期内连续{self.good_accel_steps}次放行，提前降为 {st.level.value}",
        )

    def _emit(self, st: _State, now: float, event: str, detail: str) -> None:
        self._events.append(
            {
                "ts": now,
                "client_id": st.client_id,
                "event": event,
                "level": st.level.value,
                "detail": detail,
            }
        )
        self._trim_events(st.client_id)

    # ---- 对外接口 ----

    def is_blocked(self, client_id: str, now: float) -> bool:
        """隔离期内一律拒绝；隔离到期则按退避规则自动恢复。"""
        with self._lock:
            st = self._get(client_id)
            self._touch(st, now)
            if self._advance(st, now):
                self.save()
            self._maybe_gc(now)
            return st.level is ReputationLevel.QUARANTINED

    def get_level(self, client_id: str, now: float) -> ReputationLevel:
        with self._lock:
            st = self._get(client_id)
            self._touch(st, now)
            if self._advance(st, now):
                self.save()
            self._maybe_gc(now)
            return st.level

    def record_good(self, client_id: str, now: float) -> ReputationLevel:
        """登记一次被放行的请求（表现良好），返回当前等级。

        仅对处在隔离后观察恢复期（in_recovery 的 RESTRICTED/SUSPECT）的身份
        累计 good_progress，达到 good_accel_steps 立即降一级（进度归零）——
        持续表现良好的身份因此明显快于“只按时间熬”的身份脱身；未进入观察期
        的身份不受影响（行为与旧版本一致）。这是唯一的请求驱动计入口：
        get_level/is_blocked/snapshot 都不累计，同一把锁保证并发请求不多算、
        不少算；进度变化即落盘，重启后不白攒、不重攒。
        """
        with self._lock:
            st = self._get(client_id)
            self._touch(st, now)
            if self._advance(st, now):
                self.save()
            if st.in_recovery and st.level in (
                ReputationLevel.RESTRICTED,
                ReputationLevel.SUSPECT,
            ):
                st.good_progress += 1
                if st.good_progress >= self.good_accel_steps:
                    self._good_step_down(st, now)
                self.save()  # 进度变化即落盘：重启不白攒
            self._maybe_gc(now)
            return st.level

    def record_violation(self, client_id: str, kind: str, now: float) -> ReputationLevel:
        """登记一次违规并返回新等级；可能升级或（重新）进入隔离。

        违规即回退：累积的恢复进度清零，连续违规计数 +1（该重新隔离就重新隔离）。
        """
        with self._lock:
            st = self._get(client_id)
            self._touch(st, now)
            self._advance(st, now)
            st.violations += 1
            progress_cleared = st.recovery_progress
            good_cleared = st.good_progress
            st.recovery_progress = 0
            st.good_progress = 0
            self._events.append(
                {
                    "ts": now,
                    "client_id": client_id,
                    "event": "violation",
                    "kind": kind,
                    "violations": st.violations,
                    "level_before": st.level.value,
                    "recovery_progress_cleared": progress_cleared,
                    "good_progress_cleared": good_cleared,
                }
            )
            self._trim_events(client_id)
            if st.violations >= _QUARANTINE_VIOLATIONS:
                st.quarantine_count += 1
                duration = min(
                    self.max_quarantine_seconds,
                    self.base_quarantine_seconds * 2 ** (st.quarantine_count - 1),
                )
                st.level = ReputationLevel.QUARANTINED
                st.quarantined_until = now + duration
                st.level_since = now
                st.in_recovery = False  # 隔离中不属于观察恢复期
                self._emit(
                    st, now, "quarantined",
                    f"连续{st.violations}次违规，隔离 {duration:g}s（第{st.quarantine_count}次）",
                )
            else:
                for threshold, level in _LEVEL_THRESHOLDS:
                    if st.violations >= threshold:
                        if st.level is not level:
                            st.level = level
                            st.level_since = now
                            self._emit(st, now, "escalate", f"升级为 {level.value}")
                        break
            self._maybe_gc(now)
            self.save()
            return st.level

    def snapshot(self, client_id: str, now: float) -> dict:
        with self._lock:
            st = self._get(client_id)
            self._touch(st, now)
            if self._advance(st, now):
                self.save()
            data = st.to_dict()
        data["quarantine_remaining"] = max(0.0, st.quarantined_until - now)
        return data

    def events(self, client_id: str | None = None) -> list[dict]:
        with self._lock:
            if client_id is None:
                return list(self._events)
            return [e for e in self._events if e.get("client_id") == client_id]

    # ---- 回收：闲置身份真删除、结论入归档表、事件保留边界 ----

    def _maybe_gc(self, now: float) -> None:
        """调用方需持锁。距上次回收超过 gc_interval_seconds 才执行。"""
        if now - self._last_gc >= self.gc_interval_seconds:
            self._last_gc = now
            self._gc_locked(now)

    def gc(self, now: float) -> dict:
        """显式回收：归档闲置身份、裁剪事件。返回回收统计（便于日志与测试）。"""
        with self._lock:
            self._last_gc = now
            return self._gc_locked(now)

    def _gc_locked(self, now: float) -> dict:
        reclaimed: list[str] = []
        changed = False
        for client_id, st in list(self._states.items()):
            # 先按当前时间推进状态机：隔离/观察期身份绝不在回收候选里
            if self._advance(st, now):
                changed = True
            if st.level is not ReputationLevel.NORMAL:
                continue
            if st.violations != 0:
                continue
            if now - st.last_seen < self.gc_idle_seconds:
                continue
            # 真回收：从活动状态表删除，结论性信息（quarantine_count、
            # last_seen）移入归档表；该身份的事件流水一并清除。
            self._archive.pop(client_id, None)  # 重新插入以刷新淘汰顺序
            self._archive[client_id] = {
                "quarantine_count": st.quarantine_count,
                "last_seen": st.last_seen,
                "archived_at": now,
            }
            del self._states[client_id]
            self._events = [
                e for e in self._events if e.get("client_id") != client_id
            ]
            reclaimed.append(client_id)
        expired = self._expire_archive_locked(now)
        if reclaimed or expired:
            self._events.append(
                {
                    "ts": now,
                    "client_id": None,
                    "event": "gc",
                    "reclaimed": reclaimed,
                    "archive_expired": expired,
                    "detail": (
                        f"回收闲置身份 {len(reclaimed)} 个，"
                        f"归档记录过期/淘汰 {len(expired)} 条"
                    ),
                }
            )
        if reclaimed or expired or changed:
            self.save()
        return {
            "reclaimed": reclaimed,
            "archive_expired": expired,
            "states": len(self._states),
            "archived": len(self._archive),
        }

    def _expire_archive_locked(self, now: float) -> list[str]:
        """调用方需持锁。归档记录本身也要有界：超时过期 + 超上限淘汰最旧。"""
        expired = [
            cid
            for cid, a in self._archive.items()
            if now - float(a.get("archived_at", 0.0)) >= self.gc_archive_seconds
        ]
        for cid in expired:
            del self._archive[cid]
        while len(self._archive) > self.gc_archive_max_entries:
            oldest = next(iter(self._archive))  # dict 保序，最旧插入的在最前
            del self._archive[oldest]
            expired.append(oldest)
        return expired

    # ---- 持久化 ----

    def save(self) -> None:
        """调用方通常已持锁；为避免自死锁这里不再加锁（内部单锁可重入不需要）。"""
        if not self.state_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.state_path)), exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "states": [s.to_dict() for s in self._states.values()],
                    "archive": [
                        {"client_id": cid, **a} for cid, a in self._archive.items()
                    ],
                    "events": self._events,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        os.replace(tmp, self.state_path)

    def load(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        with open(self.state_path, encoding="utf-8") as f:
            data = json.load(f)
        with self._lock:
            states: dict[str, _State] = {}
            archive: dict[str, dict] = {}
            for s in data.get("states", []):
                st = _State.from_dict(s)
                if st.archived:
                    # 旧格式迁移：历史上“归档”是留在状态表里的压缩条目，
                    # 现在统一迁入归档表（结论性字段不变）。
                    archive[st.client_id] = {
                        "quarantine_count": st.quarantine_count,
                        "last_seen": st.last_seen,
                        "archived_at": st.last_seen,
                    }
                else:
                    states[st.client_id] = st
            for a in data.get("archive", []):
                entry = dict(a)
                cid = entry.pop("client_id")
                archive[cid] = entry
            self._states = states
            self._archive = archive
            self._events = list(data.get("events", []))
