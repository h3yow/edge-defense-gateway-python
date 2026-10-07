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

表现良好加速恢复（真正按“表现”加速，而不只是熬时间）：
    观察恢复期（RESTRICTED/SUSPECT）内，身份在当前等级持续表现良好满
    0.4×recover_step_seconds（默认 2s）之后，每出现一次被放行的“良好请求”
    good_credit +1；攒满 good_requests_per_step（默认 3）即提前完成一个恢复步。
    未满 2s 之前的请求不计信用——既保证“持续表现良好”而非瞬时刷量，也避免
    并发请求在状态迁移的同一刻把信用灌进新等级。时间熬满 recover_step_seconds
    则无条件完成恢复步（不来也能慢慢恢复），两种方式谁先到谁触发，每步只兑现一次。
    => 默认配置下：持续正常发请求，隔离到期后每级约 2s+3 次良好请求即可推进，
       两级共约 4s，明显快于纯时间阶梯的 10s。中途再违规一次，good_credit/
       recovery_progress 立即清零并按连续违规计数回退，该重新隔离就重新隔离。
    good_credit 与 recovery_progress 都随状态持久化：重启后不白攒、不重攒；
    所有累加与状态迁移都在同一把锁内，并发入口不会把同一步算多次。

回收与保留（长期运行身份规模有界，而不是“打标记不删除”）：
    - 等级为 NORMAL（无违规计数、无恢复进度）且超过 gc_idle_seconds 未出现的
      活跃身份会被真正回收：
        * quarantine_count == 0（无隔离前科）：状态与事件直接删除，完全释放；
        * quarantine_count  > 0（有隔离前科）：活动状态删除、内存释放，只在独立
          的“前科归档表”里留一条最小结论（client_id + quarantine_count +
          archived_at），保证再犯时退避次数/时长与从未被回收完全一致。
    - 前科归档也是有界的：超过 gc_history_ttl_seconds（默认 7 天）未再出现的
      归档条目会被彻底遗忘。因此无论见过多少身份，长期状态规模都有上界。
    - 隔离中、观察恢复期（RESTRICTED/SUSPECT）或最近有活动的身份绝不回收；
      回收前先按当前时间推进状态机，避免把刚到期的身份误判为闲置。
    - 被归档身份再次出现时从归档表原地复活（前科续上），结论与回收前一致。
    - 每个身份的事件流水最多保留 max_events_per_client 条（超出丢弃最旧）；
      全局 gc 事件最多保留 max_gc_events 条。
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
_GOOD_BEHAVIOR_STEP_FLOOR_RATIO = 0.4  # 良好行为提前完成恢复步所需的最短持续时间比例
_GOOD_ACCEL_STEPS = 2
_GOOD_REQUESTS_PER_STEP = 3
_GC_IDLE_SECONDS = 3600.0
_GC_HISTORY_TTL_SECONDS = 7 * 24 * 3600.0
_MAX_EVENTS_PER_CLIENT = 100
_MAX_GC_EVENTS = 100
_GC_INTERVAL_SECONDS = 60.0


@dataclass
class _State:
    client_id: str
    violations: int = 0          # 当前连续违规计数（恢复成功时清零/递减）
    level: ReputationLevel = ReputationLevel.NORMAL
    quarantine_count: int = 0   # 历史进入隔离的次数（决定退避时长）
    quarantined_until: float = 0.0
    level_since: float = 0.0    # 进入当前等级的时间
    recovery_progress: int = 0  # 已完成的连续无违规恢复步数（达到阈值加速降级，违规清零）
    good_credit: int = 0        # 当前等级内累计的良好请求次数（攒满可提前完成恢复步，迁移/违规清零）
    last_seen: float = 0.0      # 最近一次出现（请求/违规/查询）的时间
    archived: bool = False      # 兼容旧持久化字段：活动身份恒为 False，归档身份不在此表中

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "violations": self.violations,
            "level": self.level.value,
            "quarantine_count": self.quarantine_count,
            "quarantined_until": self.quarantined_until,
            "level_since": self.level_since,
            "recovery_progress": self.recovery_progress,
            "good_credit": self.good_credit,
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
            good_credit=int(data.get("good_credit", 0)),
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
        good_requests_per_step: int = _GOOD_REQUESTS_PER_STEP,
        gc_idle_seconds: float = _GC_IDLE_SECONDS,
        gc_history_ttl_seconds: float = _GC_HISTORY_TTL_SECONDS,
        max_events_per_client: int = _MAX_EVENTS_PER_CLIENT,
        max_gc_events: int = _MAX_GC_EVENTS,
        gc_interval_seconds: float = _GC_INTERVAL_SECONDS,
    ) -> None:
        if good_accel_steps < 1:
            raise ValueError("good_accel_steps must be >= 1")
        if good_requests_per_step < 1:
            raise ValueError("good_requests_per_step must be >= 1")
        if gc_idle_seconds <= 0:
            raise ValueError("gc_idle_seconds must be > 0")
        if gc_history_ttl_seconds <= 0:
            raise ValueError("gc_history_ttl_seconds must be > 0")
        if max_events_per_client < 1:
            raise ValueError("max_events_per_client must be >= 1")
        if max_gc_events < 1:
            raise ValueError("max_gc_events must be >= 1")
        if gc_interval_seconds <= 0:
            raise ValueError("gc_interval_seconds must be > 0")
        self.state_path = state_path
        self.base_quarantine_seconds = base_quarantine_seconds
        self.max_quarantine_seconds = max_quarantine_seconds
        self.recover_step_seconds = recover_step_seconds
        # 良好行为提前完成一个恢复步所需的“最短持续表现时间”：默认 2s（=5s×0.4）
        self.good_behavior_step_floor = (
            recover_step_seconds * _GOOD_BEHAVIOR_STEP_FLOOR_RATIO
        )
        self.good_accel_steps = good_accel_steps
        self.good_requests_per_step = good_requests_per_step
        self.gc_idle_seconds = gc_idle_seconds
        self.gc_history_ttl_seconds = gc_history_ttl_seconds
        self.max_events_per_client = max_events_per_client
        self.max_gc_events = max_gc_events
        self.gc_interval_seconds = gc_interval_seconds
        self._lock = threading.Lock()
        self._states: dict[str, _State] = {}
        # 已回收身份的“前科归档表”：client_id -> 最小结论
        # （quarantine_count / archived_at）。与活跃状态分离，使活动状态表
        # 真正随回收缩小；归档条目本身也按 gc_history_ttl_seconds 有界遗忘。
        self._archives: dict[str, dict] = {}
        self._events: list[dict] = []
        self._last_gc: float = 0.0

    # ---- 内部：调用方需持锁，且先做时间驱动的恢复推进 ----

    def _hydrate(self, client_id: str) -> tuple[_State, bool]:
        """取活跃状态；若身份此前已被回收，则从归档表原地复活。

        返回 (状态, 是否刚复活)。复活只带回结论性字段 quarantine_count，
        其余按 NORMAL 默认值重建，因此再犯时的退避结论与回收前完全一致。
        """
        st = self._states.get(client_id)
        if st is not None:
            return st, False
        archive = self._archives.pop(client_id, None)
        st = _State(
            client_id=client_id,
            quarantine_count=int(archive["quarantine_count"]) if archive else 0,
        )
        self._states[client_id] = st
        return st, archive is not None

    def _ensure(
        self, client_id: str, now: float, emit_revive: bool
    ) -> tuple[_State, bool]:
        """取/复活状态并登记一次“出现”；返回 (状态, 是否刚复活)。

        复活时是否落事件由调用方决定（纯观测的 snapshot 不写事件）。
        """
        st, revived = self._hydrate(client_id)
        st.last_seen = now
        st.archived = False
        if revived and emit_revive:
            self._events.append(
                {
                    "ts": now,
                    "client_id": client_id,
                    "event": "revived",
                    "quarantine_count": st.quarantine_count,
                    "detail": (
                        f"已回收身份再次出现，按前科 quarantine_count="
                        f"{st.quarantine_count} 原地复活"
                    ),
                }
            )
            self._trim_events(client_id)
        return st, revived

    def _trim_events(self, client_id: str) -> None:
        """调用方需持锁。将该身份的事件裁剪到保留边界（丢弃最旧）。"""
        idx = [i for i, e in enumerate(self._events) if e.get("client_id") == client_id]
        overflow = len(idx) - self.max_events_per_client
        if overflow > 0:
            drop = set(idx[:overflow])
            self._events = [e for i, e in enumerate(self._events) if i not in drop]

    def _advance(self, st: _State, now: float) -> bool:
        """根据当前时间推进恢复状态机（隔离到期 -> 逐级退避恢复）。

        纯时间驱动：隔离到期降为 RESTRICTED；观察期每熬满一个
        recover_step_seconds 可完成一个恢复步。每个恢复步最多推进一格
        （level_since 随推进刷新），重复调用不会重复累计恢复进度。
        返回是否发生了状态迁移；调用方在迁移后落盘，保证恢复进度随重启
        完整恢复（不白攒、不重攒）。良好请求驱动的提前推进见
        _register_good_request。
        """
        changed = False
        if st.level is ReputationLevel.QUARANTINED:
            if now < st.quarantined_until:
                return False
            # 隔离到期：降为 RESTRICTED，开始观察期；连续违规计数保留 2
            st.level = ReputationLevel.RESTRICTED
            st.violations = 2
            st.level_since = now
            st.good_credit = 0
            self._emit(st, now, "quarantine_released", "隔离到期，进入限制观察期")
            changed = True
        if st.level is ReputationLevel.RESTRICTED:
            if now - st.level_since >= self.recover_step_seconds:
                self._recover_step(st, now, via="time")
                changed = True
        if st.level is ReputationLevel.SUSPECT:
            if now - st.level_since >= self.recover_step_seconds:
                self._recover_step(st, now, via="time")
                changed = True
        return changed

    def _register_good_request(self, st: _State, now: float) -> tuple[bool, bool]:
        """登记一次被放行的良好请求（调用方需持锁）。

        仅观察恢复期（RESTRICTED/SUSPECT）有效，且要求在当前等级已持续表现
        良好至少 good_behavior_step_floor（默认 0.4×recover_step_seconds=2s）：
        未熬过 floor 的请求只证明“当下正常”，不计信用（同一时刻刷量无法瞬间
        脱身，也避免并发在状态迁移的同一刻把信用灌进新等级）。熬过 floor 后
        good_credit +1，攒满 good_requests_per_step 即提前完成一个恢复步；
        熬满完整 recover_step_seconds 则由 _advance 无条件推进。每次调用最多
        推进一格；进度与信用都在锁内更新，并发请求不会把同一步算多次。

        返回 (是否发生等级迁移, 是否累计了良好信用)：两者都需由调用方落盘，
        保证重启后信用不白攒。
        """
        if st.level not in (ReputationLevel.RESTRICTED, ReputationLevel.SUSPECT):
            return False, False
        elapsed = now - st.level_since
        # 已熬满完整时间：直接走时间路径（避免重复兑现同一步）
        if elapsed >= self.recover_step_seconds:
            return self._advance(st, now), False
        # 未满最短持续时间：不计信用（防瞬时刷量、防迁移同刻并发灌入新等级）
        if elapsed < self.good_behavior_step_floor:
            return False, False
        st.good_credit += 1
        if st.good_credit < self.good_requests_per_step:
            return False, True
        self._recover_step(st, now, via="good_behavior")
        return True, True

    def _recover_step(self, st: _State, now: float, via: str) -> None:
        """完成一个无违规恢复步：进度 +1；达到加速阈值则直接跳回 NORMAL。

        via 标记本步是熬满时间（time）还是良好行为攒满（good_behavior），
        用于事件可追溯；两种路径兑现的结论完全相同。
        """
        st.recovery_progress += 1
        accelerated = st.recovery_progress >= self.good_accel_steps
        if st.level is ReputationLevel.RESTRICTED and not accelerated:
            st.level = ReputationLevel.SUSPECT
            st.violations = 1
            st.level_since = now
            st.good_credit = 0  # 新等级重新攒信用
            self._emit(
                st, now, "recover",
                f"观察期无违规（{via}），降为可疑",
                extra={"via": via},
            )
            return
        st.level = ReputationLevel.NORMAL
        st.violations = 0
        st.level_since = now
        st.good_credit = 0
        if accelerated:
            self._emit(
                st, now, "accelerated_recover",
                f"连续{st.recovery_progress}步无违规（{via}），加速恢复正常",
                extra={"via": via},
            )
        else:
            self._emit(
                st, now, "recover",
                f"观察期无违规（{via}），恢复正常",
                extra={"via": via},
            )
        st.recovery_progress = 0  # 进度已兑现，归零重新累积

    def _emit(self, st: _State, now: float, event: str, detail: str,
              extra: dict | None = None) -> None:
        entry = {
            "ts": now,
            "client_id": st.client_id,
            "event": event,
            "level": st.level.value,
            "detail": detail,
        }
        if extra:
            entry.update(extra)
        self._events.append(entry)
        self._trim_events(st.client_id)

    # ---- 对外接口 ----

    def is_blocked(self, client_id: str, now: float) -> bool:
        """隔离期内一律拒绝；隔离到期则按退避规则自动恢复。"""
        with self._lock:
            st, revived = self._ensure(client_id, now, emit_revive=True)
            changed = revived or self._advance(st, now)
            if changed:
                self.save()
            self._maybe_gc(now)
            return st.level is ReputationLevel.QUARANTINED

    def get_level(self, client_id: str, now: float) -> ReputationLevel:
        with self._lock:
            st, revived = self._ensure(client_id, now, emit_revive=True)
            changed = revived or self._advance(st, now)
            if changed:
                self.save()
            self._maybe_gc(now)
            return st.level

    def note_good_request(self, client_id: str, now: float) -> ReputationLevel:
        """登记一次“被放行的良好请求”并返回当前等级。

        仅观察恢复期身份会累计 good_credit（攒满可提前完成恢复步）；
        隔离身份的请求在引擎层已被拒绝，不会走到这里。每次迁移即落盘，
        保证重启不白攒/不重攒；锁内更新保证并发不多算。
        """
        with self._lock:
            st, revived = self._ensure(client_id, now, emit_revive=True)
            # _register_good_request 内部已处理“时间熬满”的推进，无需重复 _advance
            advanced, credited = self._register_good_request(st, now)
            if revived or advanced or credited:
                self.save()
            self._maybe_gc(now)
            return st.level

    def record_violation(self, client_id: str, kind: str, now: float) -> ReputationLevel:
        """登记一次违规并返回新等级；可能升级或（重新）进入隔离。

        违规即回退：累积的恢复进度与良好信用立即清零，连续违规计数 +1
        （该重新隔离就重新隔离）。
        """
        with self._lock:
            st, revived = self._ensure(client_id, now, emit_revive=True)
            self._advance(st, now)
            st.violations += 1
            progress_cleared = st.recovery_progress
            credit_cleared = st.good_credit
            st.recovery_progress = 0
            st.good_credit = 0
            self._events.append(
                {
                    "ts": now,
                    "client_id": client_id,
                    "event": "violation",
                    "kind": kind,
                    "violations": st.violations,
                    "level_before": st.level.value,
                    "recovery_progress_cleared": progress_cleared,
                    "good_credit_cleared": credit_cleared,
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
            # 纯观测：复活不写事件，但时间驱动的状态迁移仍需落盘（与历史行为一致）
            st, revived = self._ensure(client_id, now, emit_revive=False)
            if revived or self._advance(st, now):
                self.save()
            data = st.to_dict()
            data["quarantine_remaining"] = max(0.0, st.quarantined_until - now)
            return data

    def events(self, client_id: str | None = None) -> list[dict]:
        with self._lock:
            if client_id is None:
                return list(self._events)
            return [e for e in self._events if e.get("client_id") == client_id]

    def state_size(self) -> int:
        """当前活跃身份数（真正保存在内存中的活动状态条目数）。"""
        with self._lock:
            return len(self._states)

    def archive_size(self) -> int:
        """已回收、仅保留最小前科结论的身份数。"""
        with self._lock:
            return len(self._archives)

    # ---- 回收：闲置身份归档与事件保留边界 ----

    def _maybe_gc(self, now: float) -> None:
        """调用方需持锁。距上次回收超过 gc_interval_seconds 才执行。"""
        if now - self._last_gc >= self.gc_interval_seconds:
            self._last_gc = now
            self._gc_locked(now)

    def gc(self, now: float) -> dict:
        """显式回收：真正移除闲置活跃状态、维护前科归档、裁剪事件。

        返回统计（便于日志与测试）：
        - reclaimed：本次从活动状态表移除的全部身份；
        - archived/forgotten：其中有前科（留最小结论）/ 无前科（彻底删除）；
        - archives_expired：因超过历史保留期被遗忘的归档身份；
        - states/archives：回收后两张表的规模。
        """
        with self._lock:
            self._last_gc = now
            return self._gc_locked(now)

    def _gc_locked(self, now: float) -> dict:
        """调用方需持锁。真正回收闲置身份，并让状态规模有界。

        - 活跃状态：NORMAL、violations=0、无未兑现恢复进度、闲置超过
          gc_idle_seconds 的身份从活动状态表中删除（释放内存）；
          有隔离前科的身份在归档表里只留最小结论，无前科的直接删除；
        - 隔离中 / 观察恢复期 / 最近活动的身份一律保留（先推进状态机再判）；
        - 归档表超过 gc_history_ttl_seconds 的条目彻底遗忘；
        - 全局 gc 事件裁剪到最近 max_gc_events 条。
        """
        reclaimed: list[str] = []     # 所有从活动状态表真正移除的身份（=archived ∪ forgotten）
        archived: list[str] = []      # 有前科、转入归档表保留最小结论的身份
        forgotten: list[str] = []     # 无前科、直接彻底删除的身份
        changed = False

        for client_id in list(self._states):
            st = self._states[client_id]
            # 先按当前时间推进状态机：隔离/观察期身份绝不在回收候选里
            if self._advance(st, now):
                changed = True
            if st.level is not ReputationLevel.NORMAL:
                continue
            if st.violations != 0 or st.recovery_progress != 0:
                continue
            if now - st.last_seen < self.gc_idle_seconds:
                continue
            # 该身份的事件流水随状态一起清除
            self._events = [
                e for e in self._events if e.get("client_id") != client_id
            ]
            del self._states[client_id]
            reclaimed.append(client_id)
            if st.quarantine_count > 0:
                # 只保留影响后续退避结论的最小信息
                self._archives[client_id] = {
                    "client_id": client_id,
                    "quarantine_count": st.quarantine_count,
                    "archived_at": now,
                }
                archived.append(client_id)
            else:
                forgotten.append(client_id)

        # 前科归档同样有界：超过历史保留期未再出现则彻底遗忘
        expired = [
            cid for cid, a in self._archives.items()
            if now - float(a["archived_at"]) >= self.gc_history_ttl_seconds
        ]
        for cid in expired:
            del self._archives[cid]

        if reclaimed or expired:
            self._events.append(
                {
                    "ts": now,
                    "client_id": None,
                    "event": "gc",
                    "reclaimed": reclaimed,
                    "archived": archived,
                    "forgotten": forgotten,
                    "archives_expired": expired,
                    "detail": (
                        f"回收闲置身份 {len(reclaimed)} 个"
                        f"（归档有前科 {len(archived)} 个，"
                        f"彻底清除无前科 {len(forgotten)} 个），"
                        f"遗忘过期归档 {len(expired)} 个"
                    ),
                }
            )
            # 全局 gc/无主事件也设上界，避免事件列表自身无限增长
            gc_events = [e for e in self._events if e.get("client_id") is None]
            overflow = len(gc_events) - self.max_gc_events
            if overflow > 0:
                drop = set(id(e) for e in gc_events[:overflow])
                self._events = [e for e in self._events if id(e) not in drop]

        if reclaimed or expired or changed:
            self.save()
        return {
            "reclaimed": reclaimed,
            "archived": archived,
            "forgotten": forgotten,
            "archives_expired": expired,
            "states": len(self._states),
            "archives": len(self._archives),
        }

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
                    "archives": list(self._archives.values()),
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
            # 先加载新格式的前科归档表，再用旧格式 states 里 archived=true 的
            # 条目补充迁移（不能反过来覆盖，否则迁移结果会被丢掉）
            self._archives = {
                a["client_id"]: {
                    "client_id": a["client_id"],
                    "quarantine_count": int(a["quarantine_count"]),
                    "archived_at": float(a["archived_at"]),
                }
                for a in data.get("archives", [])
            }
            self._states = {}
            for raw in data.get("states", []):
                st = _State.from_dict(raw)
                # 兼容旧版本：旧回收只打 archived 标记、状态仍留在表内。
                # 迁移时将其转入前科归档表并从活动表移除，真正释放规模。
                if st.archived:
                    self._archives[st.client_id] = {
                        "client_id": st.client_id,
                        "quarantine_count": st.quarantine_count,
                        "archived_at": float(raw.get("last_seen", 0.0)),
                    }
                    continue
                self._states[st.client_id] = st
            self._events = list(data.get("events", []))
