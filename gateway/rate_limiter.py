"""基于身份的滑动窗口限流，线程安全。

- 每个 client_id 独立计数；
- check 为“判定 + 登记”的原子操作，并发下不丢不重；
- 窗口外的时间戳被淘汰，过期后额度自动恢复；
- 阈值边界确定：第 limit 次放行，第 limit+1 次拒绝；
- 支持信誉分档：check/snapshot 可按当次身份等级传入生效阈值，
  不传时使用构造时的统一阈值（老行为不变）。同一身份的窗口历史只有一份，
  等级一旦变化，下一次请求立即按新档位阈值判定。
"""

from __future__ import annotations

import threading


class SlidingWindowRateLimiter:
    """每个 client_id 维护一个时间戳列表，表示窗口内的请求。"""

    def __init__(self, limit: int = 10, window_seconds: float = 1.0) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.limit = limit
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def _effective_limit(self, limit: int | None) -> int:
        effective = self.limit if limit is None else limit
        if effective < 0:
            raise ValueError("limit must be >= 0")
        return effective

    def _evict(self, hits: list[float], now: float) -> None:
        """调用方需持锁。删除窗口左边界之前的时间戳（左闭右开）。"""
        boundary = now - self.window_seconds
        # 时间戳单调追加，找到第一个 > boundary 的位置即可
        i = 0
        for i, ts in enumerate(hits):
            if ts > boundary:
                break
        else:
            i = len(hits)
        # 全部 <= boundary 时 i == len，清空
        if i > 0:
            del hits[:i]

    def check(self, client_id: str, now: float, limit: int | None = None) -> bool:
        """判定并登记一次请求：窗口内计数 < 生效阈值则追加时间戳并放行。

        limit 为 None 时使用构造阈值；否则按调用方给定的分档阈值判定
        （窗口历史仍是同一份，分档切换即时生效）。
        """
        effective = self._effective_limit(limit)
        with self._lock:
            hits = self._hits.setdefault(client_id, [])
            self._evict(hits, now)
            if len(hits) >= effective:
                return False
            hits.append(now)
            return True

    def remaining(
        self, client_id: str, now: float, limit: int | None = None
    ) -> int:
        """查询当前剩余额度，不登记请求（只读，不加写）。"""
        effective = self._effective_limit(limit)
        with self._lock:
            hits = self._hits.get(client_id)
            if not hits:
                return effective
            self._evict(hits, now)
            return max(0, effective - len(hits))

    def reset(self, client_id: str | None = None) -> None:
        """清空计数（测试/运维/不活跃身份回收使用）。"""
        with self._lock:
            if client_id is None:
                self._hits.clear()
            else:
                self._hits.pop(client_id, None)

    def snapshot(
        self, client_id: str, now: float, limit: int | None = None
    ) -> dict:
        """返回该身份窗口状态快照，用于日志与可解释判定。"""
        effective = self._effective_limit(limit)
        with self._lock:
            hits = list(self._hits.get(client_id, ()))
        # 快照计算窗口内数量
        boundary = now - self.window_seconds
        in_window = [ts for ts in hits if ts > boundary]
        return {
            "client_id": client_id,
            "limit": effective,
            "window_seconds": self.window_seconds,
            "used": len(in_window),
            "remaining": max(0, effective - len(in_window)),
            "timestamps": in_window,
        }
