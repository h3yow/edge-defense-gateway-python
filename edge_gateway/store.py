"""Persistent state + audit log storage (JSON / JSONL on local disk)."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Protocol


class StateStore(Protocol):
    def load_states(self) -> dict[str, dict[str, Any]]: ...

    def save_states(self, states: dict[str, dict[str, Any]]) -> None: ...

    def append_audit(self, event: dict[str, Any]) -> None: ...

    def read_audit(self) -> list[dict[str, Any]]: ...


class JsonFileStore:
    """JSON state file + append-only JSONL audit trail.

    State writes are atomic (temp file + os.replace); every mutation is also
    recorded in the JSONL audit log so state changes remain traceable after
    process restart.
    """

    def __init__(self, state_path: str | Path, audit_path: str | Path) -> None:
        self.state_path = Path(state_path)
        self.audit_path = Path(audit_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def load_states(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            if not self.state_path.exists():
                return {}
            with self.state_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise TypeError(f"state file {self.state_path} must contain a JSON object")
            return data

    def save_states(self, states: dict[str, dict[str, Any]]) -> None:
        with self._lock:
            tmp_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
            with tmp_path.open("w", encoding="utf-8") as fh:
                json.dump(states, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.state_path)

    def append_audit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self._lock, self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def read_audit(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.audit_path.exists():
                return []
            events: list[dict[str, Any]] = []
            with self.audit_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
            return events


class InMemoryStore:
    """Non-persistent store, handy for isolated unit tests."""

    def __init__(self) -> None:
        self._states: dict[str, dict[str, Any]] = {}
        self._audit: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def load_states(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            # Return a deep-ish copy so callers cannot mutate stored data.
            return json.loads(json.dumps(self._states))

    def save_states(self, states: dict[str, dict[str, Any]]) -> None:
        with self._lock:
            self._states = json.loads(json.dumps(states))

    def append_audit(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._audit.append(dict(event))

    def read_audit(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._audit]
