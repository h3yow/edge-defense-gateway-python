"""来源信誉：违规累积、逐级升级、隔离与退避恢复。

等级演进（连续违规逐级升级）：
    NORMAL --1--> SUSPECT --2--> RESTRICTED --3--> QUARANTINED

隔离：
    达到升级阈值即进入隔离，隔离时长 = base * 2 ** (quarantine_count - 1)，
    第 1 次 1 个 base、第 2 次 2 个、第 3 次 4 个……（指数退避，封顶）。

恢复（隔离到期后的观察恢复期，带“良好表现加速”）：
    QUARANTINED 到期自动降为 RESTRICTED（观察期）；
    恢复期进度 = 自上次推进点以来累计的良好秒数：
      - 时间自然流逝每秒计 1 秒（保底，与历史行为完全一致）；
      - 观察期内每经过 good_bonus_interval_seconds 且期间没有违规，
        来一次干净请求可额外获得 good_bonus_seconds 进度；
      - 进度满 recover_step_seconds 即降一级（RESTRICTED -> SUSPECT -> NORMAL）；
      - 任何新违规立即清零进度与奖励锚点，并按连续违规规则回退/重新隔离。
    进度随每次变化落盘，重启后按锚点继续累计：不白攒、不重复攒。

回收（长时间未出现的身份与历史记录有界保留）：
    - 活跃身份 last_seen 超过 inactive_ttl_seconds 才允许回收；
      隔离中、观察恢复中（restricted/suspect 且仍有进度上下文）的身份绝不回收；
    - 回收不是物理删除：身份变为 dormant（休眠），仅保留 client_id 与
      历史隔离次数 quarantine_count（决定下次再犯时的退避倍数），
      其余结论按“全新正常身份”处理——与回收前“早已恢复正常”的结论一致；
    - 休眠超过 dormant_ttl_seconds，或休眠身份数量超过 max_dormant_identities
      （按最近活动淘汰最旧），才真正遗忘；
    - 事件流水最多保留 max_events 条（最旧先丢）；被回收身份的事件一并删除。
    回收状态同样落盘，重启复现结论一致。

持久化：
    状态（含恢复期进度、休眠身份）与事件流水以 JSON 落盘，进程重启后可复现；
    每次状态变更都追加事件，形成可追溯记录。
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
_GOOD_BONUS_SECONDS = 1.0
_GOOD_BONUS_INTERVAL_SECONDS = 0.5
_INACTIVE_TTL_SECONDS = 3600.0
_DORMANT_TTL_SECONDS = 86400.0
_MAX_DORMANT_IDENTITIES = 1000
_MAX_EVENTS = 2000


@dataclass
class _State:
    client_id: str
    violations: int = 0          # 当前连续违规计数（恢复成功时清零/递减）
    level: ReputationLevel = ReputationLevel.NORMAL
    quarantine_count: int = 0   # 历史进入隔离的次数（决定退避时长）
    quarantined_until: float = 0.0
    level_since: float = 0.0    # 进入当前等级的时间
    good_progress: float = 0.0  # 观察恢复期已累计的良好秒数
    last_seen: float = 0.0      # 最近一次活动时间（回收判定依据）
    last_bonus_at: float = 0.0  # 最近一次干净请求奖励时间（重复领取判定）

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "violations": self.violations,
            "level": self.level.value,
            "quarantine_count": self.quarantine_count,
            "quarantined_until": self.quarantined_until,
            "level_since": self.level_since,
            "good_progress": self.good_progress,
            "last_seen": self.last_seen,
            "last_bonus_at": self.last_bonus_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "_State":
        # 兼容旧版本落盘文件：新字段缺失时取默认/等价初值
        return cls(
            client_id=data["client_id"],
            violations=int(data.get("violations", 0)),
            level=ReputationLevel(data["level"]),
            quarantine_count=int(data.get("quarantine_count", 0)),
            quarantined_until=float(data.get("quarantined_until", 0.0)),
            level_since=float(data.get("level_since", 0.0)),
            good_progress=float(data.get("good_progress", 0.0)),
            last_seen=float(data.get("last_seen", data.get("level_since", 0.0))),
            last_bonus_at=float(data.get("last_bonus_at", 0.0)),
        )


@dataclass(frozen=True)
class _Dormant:
    """休眠身份：仅保留历史隔离次数与最近活动时间。"""

    client_id: str
    quarantine_count: int
    last_seen: float

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "quarantine_count": self.quarantine_count,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "_Dormant":
        return cls(
            client_id=data["client_id"],
            quarantine_count=int(data.get("quarantine_count", 0)),
            last_seen=float(data.get("last_seen", 0.0)),
        )


class ReputationManager:
    def __init__(
        self,
        state_path: str | None = None,
        base_quarantine_seconds: float = _BASE_QUARANTINE_SECONDS,
        max_quarantine_seconds: float = _MAX_QUARANTINE_SECONDS,
        recover_step_seconds: float = _RECOVER_STEP_SECONDS,
        good_bonus_seconds: float = _GOOD_BONUS_SECONDS,
        good_bonus_interval_seconds: float = _GOOD_BONUS_INTERVAL_SECONDS,
        inactive_ttl_seconds: float = _INACTIVE_TTL_SECONDS,
        dormant_ttl_seconds: float = _DORMANT_TTL_SECONDS,
        max_dormant_identities: int = _MAX_DORMANT_IDENTITIES,
        max_events: int = _MAX_EVENTS,
    ) -> None:
        self.state_path = state_path
        self.base_quarantine_seconds = base_quarantine_seconds
        self.max_quarantine_seconds = max_quarantine_seconds
        self.recover_step_seconds = recover_step_seconds
        self.good_bonus_seconds = good_bonus_seconds
        self.good_bonus_interval_seconds = good_bonus_interval_seconds
        self.inactive_ttl_seconds = inactive_ttl_seconds
        self.dormant_ttl_seconds = dormant_ttl_seconds
        self.max_dormant_identities = max_dormant_identities
        self.max_events = max_events
        self._lock = threading.Lock()
        self._states: dict[str, _State] = {}
        self._dormant: dict[str, _Dormant] = {}
        self._events: list[dict] = []

    # ---- 内部：调用方需持锁 ----

    def _touch(self, st: _State, now: float) -> None:
        if now > st.last_seen:
            st.last_seen = now

    def _get(self, client_id: str, now: float | None = None) -> _State:
        """取活跃状态；身份处于休眠则唤醒（仅带回历史隔离次数）。"""
        st = self._states.get(client_id)
        if st is None:
            dormant = self._dormant.pop(client_id, None)
            qc = dormant.quarantine_count if dormant else 0
            st = _State(client_id=client_id, quarantine_count=qc)
            if dormant is not None:
                st.last_seen = dormant.last_seen
            # 先纳入活跃集合，再发唤醒事件（保证同轮回收的事件过滤不漏）
            self._states[client_id] = st
            if dormant is not None:
                self._emit(st, now or st.last_seen, "revived", "休眠身份重新出现")
        if now is not None:
            self._touch(st, now)
        return st

    def _in_probation(self, st: _State) -> bool:
        """观察恢复期内：受限或可疑（隔离与正常都不算）。"""
        return st.level in (ReputationLevel.RESTRICTED, ReputationLevel.SUSPECT)

    def _reset_progress(self, st: _State) -> None:
        """清零良好表现进度与奖励锚点（违规回退时调用）。"""
        st.good_progress = 0.0
        st.last_bonus_at = 0.0

    def _consume_step_if_ready(self, st: _State, now: float) -> None:
        """进度满一个观察步则降一级；每次推进最多降一级（与历史语义一致）。"""
        if st.good_progress + 1e-9 < self.recover_step_seconds:
            return
        if st.level is ReputationLevel.RESTRICTED:
            st.level = ReputationLevel.SUSPECT
            st.violations = 1
            st.good_progress = 0.0
            st.last_bonus_at = 0.0
            st.level_since = now
            self._emit(st, now, "recover", "观察期持续良好，降为可疑")
        elif st.level is ReputationLevel.SUSPECT:
            st.level = ReputationLevel.NORMAL
            st.violations = 0
            st.good_progress = 0.0
            st.last_bonus_at = 0.0
            st.level_since = now
            self._emit(st, now, "recover", "观察期持续良好，恢复正常")

    def _advance(self, st: _State, now: float) -> None:
        """根据当前时间推进恢复状态机（隔离到期 -> 良好进度累计 -> 逐级退避恢复）。"""
        if st.level is ReputationLevel.QUARANTINED:
            if now < st.quarantined_until:
                return
            # 隔离到期：降为 RESTRICTED，开始观察期；连续违规计数保留 2
            st.level = ReputationLevel.RESTRICTED
            st.violations = 2
            st.level_since = now
            st.good_progress = 0.0
            st.last_bonus_at = 0.0
            self._emit(st, now, "quarantine_released", "隔离到期，进入限制观察期")
        if self._in_probation(st):
            # 时间自然流逝：每秒 1 秒进度（保底路径，与老行为一致）
            elapsed = now - st.level_since
            if elapsed > st.good_progress:
                st.good_progress = elapsed
            self._consume_step_if_ready(st, now)

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

    # ---- 对外接口 ----

    def is_blocked(self, client_id: str, now: float) -> bool:
        """隔离期内一律拒绝；隔离到期则按退避规则自动恢复。"""
        with self._lock:
            st = self._get(client_id, now)
            self._advance(st, now)
            return st.level is ReputationLevel.QUARANTINED

    def get_level(self, client_id: str, now: float) -> ReputationLevel:
        with self._lock:
            st = self._get(client_id, now)
            self._advance(st, now)
            return st.level

    def note_clean_activity(self, client_id: str, now: float) -> ReputationLevel:
        """登记一次“未命中规则”的请求活动。

        - 更新最近活动时间（回收判定依据）；
        - 观察恢复期内，按节流间隔发放良好表现进度奖励（并发安全，不重复领取）；
        - 返回推进后的等级。
        """
        changed = False
        with self._lock:
            st = self._get(client_id, now)
            self._touch(st, now)
            self._advance(st, now)
            if self._in_probation(st) and self.good_bonus_seconds > 0:
                if st.last_bonus_at <= 0.0:
                    # 进入观察期后的第一次干净请求：锚点初始化为进入时间，
                    # 使“经过一个 interval”语义与时间轴对齐
                    st.last_bonus_at = st.level_since
                if now - st.last_bonus_at + 1e-9 >= self.good_bonus_interval_seconds:
                    st.good_progress += self.good_bonus_seconds
                    st.last_bonus_at = now
                    changed = True
                    self._emit(
                        st, now, "good_progress",
                        f"观察期表现良好，进度 +{self.good_bonus_seconds:g}s "
                        f"= {st.good_progress:g}/{self.recover_step_seconds:g}s",
                    )
                    self._consume_step_if_ready(st, now)
            if changed:
                self.save()
            return st.level

    def record_violation(self, client_id: str, kind: str, now: float) -> ReputationLevel:
        """登记一次违规并返回新等级；可能升级或（重新）进入隔离。"""
        with self._lock:
            st = self._get(client_id, now)
            self._touch(st, now)
            self._advance(st, now)
            # 观察恢复期内再违规：良好进度立即清零
            if self._in_probation(st) and st.good_progress > 0.0:
                self._reset_progress(st)
                self._emit(st, now, "progress_reset", "观察期再次违规，恢复进度清零")
            st.violations += 1
            self._events.append(
                {
                    "ts": now,
                    "client_id": client_id,
                    "event": "violation",
                    "kind": kind,
                    "violations": st.violations,
                    "level_before": st.level.value,
                }
            )
            if st.violations >= _QUARANTINE_VIOLATIONS:
                st.quarantine_count += 1
                duration = min(
                    self.max_quarantine_seconds,
                    self.base_quarantine_seconds * 2 ** (st.quarantine_count - 1),
                )
                st.level = ReputationLevel.QUARANTINED
                st.quarantined_until = now + duration
                st.level_since = now
                st.good_progress = 0.0
                st.last_bonus_at = 0.0
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
                            st.good_progress = 0.0
                            st.last_bonus_at = 0.0
                            self._emit(st, now, "escalate", f"升级为 {level.value}")
                        break
            self.save()
            return st.level

    def snapshot(self, client_id: str, now: float) -> dict:
        with self._lock:
            st = self._get(client_id, now)
            self._advance(st, now)
            data = st.to_dict()
        data["quarantine_remaining"] = max(0.0, st.quarantined_until - now)
        data["recover_progress"] = st.good_progress
        data["recover_step_seconds"] = self.recover_step_seconds
        return data

    def events(self, client_id: str | None = None) -> list[dict]:
        with self._lock:
            if client_id is None:
                return list(self._events)
            return [e for e in self._events if e.get("client_id") == client_id]

    # ---- 回收与有界保留（调用方需持锁的内部版本 + 公开入口） ----

    def _reap_locked(self, now: float) -> dict:
        reaped: list[str] = []
        forgotten: list[str] = []
        for cid, st in list(self._states.items()):
            # 最近有活动：保留全部状态
            if now - st.last_seen <= self.inactive_ttl_seconds:
                continue
            # 隔离中绝不回收
            if st.level is ReputationLevel.QUARANTINED:
                continue
            # 观察恢复期中绝不回收（restricted/suspect）
            if self._in_probation(st):
                continue
            # 正常且长期不活跃：软回收为休眠身份
            self._states.pop(cid)
            self._dormant[cid] = _Dormant(
                client_id=cid,
                quarantine_count=st.quarantine_count,
                last_seen=st.last_seen,
            )
            reaped.append(cid)
            # 被回收身份的事件流水一并删除（历史记录有界保留）
            self._events = [e for e in self._events if e.get("client_id") != cid]
        # 休眠身份的有界保留：超时遗忘 + 超量按最近活动淘汰最旧
        for cid, d in list(self._dormant.items()):
            if now - d.last_seen > self.dormant_ttl_seconds:
                self._dormant.pop(cid)
                forgotten.append(cid)
        overflow = len(self._dormant) - self.max_dormant_identities
        if overflow > 0:
            oldest = sorted(self._dormant, key=lambda c: self._dormant[c].last_seen)
            for cid in oldest[:overflow]:
                self._dormant.pop(cid)
                forgotten.append(cid)
        # 事件流水有界：最旧先丢
        if len(self._events) > self.max_events:
            self._events = self._events[-self.max_events:]
        return {"reaped": reaped, "forgotten": forgotten}

    def reap_inactive(self, now: float) -> dict:
        """回收长期不活跃身份并裁剪历史，返回回收/遗忘清单。"""
        with self._lock:
            result = self._reap_locked(now)
            # 回收、遗忘、事件裁剪任一发生都需要持久化；无条件落盘也无妨（原子替换）
            self.save()
            return result

    def dormant_identities(self) -> dict[str, dict]:
        """返回休眠身份视图（测试/运维使用）。"""
        with self._lock:
            return {cid: d.to_dict() for cid, d in self._dormant.items()}

    # ---- 持久化 ----

    def save(self) -> None:
        """调用方通常已持锁；为避免自死锁这里不再加锁（内部单锁可重入不需要）。"""
        if not self.state_path:
            return
        # 历史记录有界保留：任何落盘前都先裁剪内存中的事件流水（最旧先丢）
        if len(self._events) > self.max_events:
            self._events = self._events[-self.max_events:]
        os.makedirs(os.path.dirname(os.path.abspath(self.state_path)), exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "states": [s.to_dict() for s in self._states.values()],
                    "dormant": [d.to_dict() for d in self._dormant.values()],
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
            self._dormant = {
                d["client_id"]: _Dormant.from_dict(d)
                for d in data.get("dormant", [])
            }
            self._events = list(data.get("events", []))
