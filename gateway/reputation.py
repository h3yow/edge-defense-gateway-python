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
    每完成一个无违规恢复步，recovery_progress +1；进度达到
    good_accel_steps（默认 2）时立即直接降为 NORMAL（跳级兑现，进度清零）。
    观察期内一旦再违规：进度清零、按连续违规计数立即回退（该隔离就隔离）。
    进度随状态一起持久化，进程重启后不重攒、不白攒。

回收与保留（防止长期运行状态无限膨胀）：
    - 等级为 NORMAL 且超过 gc_idle_seconds 未出现的身份会被“归档”：只保留
      影响后续结论的最小信息（quarantine_count 等），其余字段压缩、事件清除；
      再次出现时原地复活，结论与回收前完全一致（不会退化成“从没见过”）。
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


@dataclass
class _State:
    client_id: str
    violations: int = 0          # 当前连续违规计数（恢复成功时清零/递减）
    level: ReputationLevel = ReputationLevel.NORMAL
    quarantine_count: int = 0   # 历史进入隔离的次数（决定退避时长）
    quarantined_until: float = 0.0
    level_since: float = 0.0    # 进入当前等级的时间
    recovery_progress: int = 0  # 连续无违规恢复步数（达到阈值加速降级，违规清零）
    last_seen: float = 0.0      # 最近一次出现（请求/违规/查询）的时间
    archived: bool = False      # 是否已被回收压缩（仅保留结论性字段）

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "violations": self.violations,
            "level": self.level.value,
            "quarantine_count": self.quarantine_count,
            "quarantined_until": self.quarantined_until,
            "level_since": self.level_since,
            "recovery_progress": self.recovery_progress,
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
    ) -> None:
        if good_accel_steps < 1:
            raise ValueError("good_accel_steps must be >= 1")
        if gc_idle_seconds <= 0:
            raise ValueError("gc_idle_seconds must be > 0")
        if max_events_per_client < 1:
            raise ValueError("max_events_per_client must be >= 1")
        self.state_path = state_path
        self.base_quarantine_seconds = base_quarantine_seconds
        self.max_quarantine_seconds = max_quarantine_seconds
        self.recover_step_seconds = recover_step_seconds
        self.good_accel_steps = good_accel_steps
        self.gc_idle_seconds = gc_idle_seconds
        self.max_events_per_client = max_events_per_client
        self.gc_interval_seconds = gc_interval_seconds
        self._lock = threading.Lock()
        self._states: dict[str, _State] = {}
        self._events: list[dict] = []
        self._last_gc: float = 0.0

    # ---- 内部：调用方需持锁，且先做时间驱动的恢复推进 ----

    def _get(self, client_id: str) -> _State:
        return self._states.setdefault(client_id, _State(client_id=client_id))

    def _touch(self, st: _State, now: float) -> None:
        """登记一次“出现”：刷新 last_seen；已归档身份原地复活。

        归档只压缩存储，结论性字段（quarantine_count 等）始终保留，
        因此复活后的一切判定结论与回收前完全一致。
        """
        st.last_seen = now
        st.archived = False

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
        if accelerated:
            self._emit(
                st, now, "accelerated_recover",
                f"连续{st.recovery_progress}步无违规，加速恢复正常",
            )
        else:
            self._emit(st, now, "recover", "观察期无违规，恢复正常")
        st.recovery_progress = 0  # 进度已兑现，归零重新累积

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
            st.recovery_progress = 0
            self._events.append(
                {
                    "ts": now,
                    "client_id": client_id,
                    "event": "violation",
                    "kind": kind,
                    "violations": st.violations,
                    "level_before": st.level.value,
                    "recovery_progress_cleared": progress_cleared,
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

    # ---- 回收：闲置身份归档与事件保留边界 ----

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
        for st in self._states.values():
            if st.archived:
                continue
            # 先按当前时间推进状态机：隔离/观察期身份绝不在回收候选里
            if self._advance(st, now):
                changed = True
            if st.level is not ReputationLevel.NORMAL:
                continue
            if st.violations != 0:
                continue
            if now - st.last_seen < self.gc_idle_seconds:
                continue
            # 归档：仅保留影响后续结论的 quarantine_count / last_seen，
            # 其余字段本就是 NORMAL 默认值；该身份的事件流水一并清除。
            st.archived = True
            st.quarantined_until = 0.0
            st.level_since = 0.0
            st.recovery_progress = 0
            self._events = [
                e for e in self._events if e.get("client_id") != st.client_id
            ]
            reclaimed.append(st.client_id)
        if reclaimed:
            self._events.append(
                {
                    "ts": now,
                    "client_id": None,
                    "event": "gc",
                    "reclaimed": reclaimed,
                    "detail": f"归档闲置身份 {len(reclaimed)} 个",
                }
            )
        if reclaimed or changed:
            self.save()
        return {"reclaimed": reclaimed, "states": len(self._states)}

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
            self._states = {
                s["client_id"]: _State.from_dict(s) for s in data.get("states", [])
            }
            self._events = list(data.get("events", []))
