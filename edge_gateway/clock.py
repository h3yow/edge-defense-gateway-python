"""Injectable clock so time-dependent behavior is deterministic in tests."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float: ...


class SystemClock:
    """Wall-clock time, used in production."""

    def now(self) -> float:
        return time.time()


class FakeClock:
    """Deterministic, manually advanced clock for tests."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("cannot advance backwards")
        self._t += seconds

    def set(self, value: float) -> None:
        self._t = float(value)
