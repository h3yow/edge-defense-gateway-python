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


@dataclass
class _State:
    client_id: str
    violations: int = 0          # 当前连续违规计数（恢复成功时清零/递减）
    level: ReputationLevel = ReputationLevel.NORMAL
    quarantine_count: int = 0   # 历史进入隔离的次数（决定退避时长）
    quarantined_until: float = 0.0
    level_since: float = 0.0    # 进入当前等级的时间

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "violations": self.violations,
            "level": self.level.value,
            "quarantine_count": self.quarantine_count,
            "quarantined_until": self.quarantined_until,
            "level_since": self.level_since,
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
        )


class ReputationManager:
    def __init__(
        self,
        state_path: str | None = None,
        base_quarantine_seconds: float = _BASE_QUARANTINE_SECONDS,
        max_quarantine_seconds: float = _MAX_QUARANTINE_SECONDS,
        recover_step_seconds: float = _RECOVER_STEP_SECONDS,
    ) -> None:
        self.state_path = state_path
        self.base_quarantine_seconds = base_quarantine_seconds
        self.max_quarantine_seconds = max_quarantine_seconds
        self.recover_step_seconds = recover_step_seconds
        self._lock = threading.Lock()
        self._states: dict[str, _State] = {}
        self._events: list[dict] = []

    # ---- 内部：调用方需持锁，且先做时间驱动的恢复推进 ----

    def _get(self, client_id: str) -> _State:
        return self._states.setdefault(client_id, _State(client_id=client_id))

    def _advance(self, st: _State, now: float) -> None:
        """根据当前时间推进恢复状态机（隔离到期 -> 逐级退避恢复）。"""
        if st.level is ReputationLevel.QUARANTINED:
            if now < st.quarantined_until:
                return
            # 隔离到期：降为 RESTRICTED，开始观察期；连续违规计数保留 2
            st.level = ReputationLevel.RESTRICTED
            st.violations = 2
            st.level_since = now
            self._emit(st, now, "quarantine_released", "隔离到期，进入限制观察期")
        if st.level is ReputationLevel.RESTRICTED:
            if now - st.level_since >= self.recover_step_seconds:
                st.level = ReputationLevel.SUSPECT
                st.violations = 1
                st.level_since = now
                self._emit(st, now, "recover", "观察期无违规，降为可疑")
        if st.level is ReputationLevel.SUSPECT:
            if now - st.level_since >= self.recover_step_seconds:
                st.level = ReputationLevel.NORMAL
                st.violations = 0
                st.level_since = now
                self._emit(st, now, "recover", "观察期无违规，恢复正常")

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
            st = self._get(client_id)
            self._advance(st, now)
            return st.level is ReputationLevel.QUARANTINED

    def get_level(self, client_id: str, now: float) -> ReputationLevel:
        with self._lock:
            st = self._get(client_id)
            self._advance(st, now)
            return st.level

    def record_violation(self, client_id: str, kind: str, now: float) -> ReputationLevel:
        """登记一次违规并返回新等级；可能升级或（重新）进入隔离。"""
        with self._lock:
            st = self._get(client_id)
            self._advance(st, now)
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
            self.save()
            return st.level

    def snapshot(self, client_id: str, now: float) -> dict:
        with self._lock:
            st = self._get(client_id)
            self._advance(st, now)
            data = st.to_dict()
        data["quarantine_remaining"] = max(0.0, st.quarantined_until - now)
        return data

    def events(self, client_id: str | None = None) -> list[dict]:
        with self._lock:
            if client_id is None:
                return list(self._events)
            return [e for e in self._events if e.get("client_id") == client_id]

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
