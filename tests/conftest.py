"""Pytest configuration: print decision evidence + client state snapshots.

Run ``uv run pytest -s -o log_cli=true`` to watch the judgments live.
"""

from __future__ import annotations

import logging


def pytest_configure(config):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    logging.getLogger("tests").setLevel(logging.INFO)
