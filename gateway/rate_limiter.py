"""基于身份的滑动窗口限流，线程安全。

- 每个 client_id 独立计数；
- check 为“判定 + 登记”的原子操作，并发下不丢不重；
- 窗口外的时间戳被淘汰，过期后额度自动恢复；
- 阈值边界确定：第 limit 次放行，第 limit+1 次拒绝；
- check/remaining/snapshot 支持按次传入 limit（分档限流），缺省用构造值；
- 窗口清空后身份条目即删除，长时间运行身份表不无限膨胀。
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

    def _resolve(self, limit: int | None) -> int:
        """按次额度缺省回退到构造值；额度必须 >= 1。"""
        if limit is None:
            return self.limit
        if limit < 1:
            raise ValueError("limit must be >= 1")
        return limit

    def check(self, client_id: str, now: float, limit: int | None = None) -> bool:
        """判定并登记一次请求：窗口内计数 < limit 则追加时间戳并放行。"""
        limit = self._resolve(limit)
        with self._lock:
            hits = self._hits.setdefault(client_id, [])
            self._evict(hits, now)
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def remaining(self, client_id: str, now: float, limit: int | None = None) -> int:
        """查询当前剩余额度，不登记请求（只读，不加写）。"""
        limit = self._resolve(limit)
        with self._lock:
            hits = self._hits.get(client_id)
            if not hits:
                self._hits.pop(client_id, None)
                return limit
            self._evict(hits, now)
            if not hits:
                del self._hits[client_id]
                return limit
            return max(0, limit - len(hits))

    def reset(self, client_id: str | None = None) -> None:
        """清空计数（测试/运维使用）。"""
        with self._lock:
            if client_id is None:
                self._hits.clear()
            else:
                self._hits.pop(client_id, None)

    def snapshot(self, client_id: str, now: float, limit: int | None = None) -> dict:
        """返回该身份窗口状态快照，用于日志与可解释判定。"""
        limit = self._resolve(limit)
        with self._lock:
            hits = list(self._hits.get(client_id, ()))
        # 快照计算窗口内数量
        boundary = now - self.window_seconds
        in_window = [ts for ts in hits if ts > boundary]
        return {
            "client_id": client_id,
            "limit": limit,
            "window_seconds": self.window_seconds,
            "used": len(in_window),
            "remaining": max(0, limit - len(in_window)),
            "timestamps": in_window,
        }
