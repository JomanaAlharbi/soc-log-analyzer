"""Shared, deterministic test helpers. All data is synthetic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.log_parser import FAILURE, SUCCESS, LogEvent, classify_ip
import ipaddress

# Monday 2026-03-02 09:00 UTC: inside default business hours (08:00-18:00, Mon-Fri)
BASE_TIME = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)
HEADER = "timestamp,username,source_ip,event_type\n"


@pytest.fixture
def base_time() -> datetime:
    return BASE_TIME


@pytest.fixture
def make_event():
    """Factory: make_event(offset_seconds, user, ip, kind) -> LogEvent."""
    counter = {"n": 1}

    def _make(offset_seconds: float = 0, username: str = "alice",
              ip: str = "192.0.2.10", kind: str = FAILURE,
              at: datetime | None = None) -> LogEvent:
        counter["n"] += 1
        stamp = (at or BASE_TIME) + timedelta(seconds=offset_seconds)
        return LogEvent(
            line_number=counter["n"],
            timestamp=stamp,
            username=username,
            source_ip=ip,
            event_type=kind,
            ip_category=classify_ip(ipaddress.ip_address(ip)),
        )

    return _make


@pytest.fixture
def write_csv(tmp_path: Path):
    """Factory: write_csv(text, name) -> Path of a file inside tmp_path."""

    def _write(text: str, name: str = "log.csv") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8", newline="")
        return path

    return _write


@pytest.fixture
def sample_log() -> Path:
    return Path(__file__).resolve().parent.parent / "logs" / "sample_auth.csv"


__all__ = ["BASE_TIME", "HEADER", "SUCCESS", "FAILURE"]
