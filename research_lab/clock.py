"""Injected clocks. Nothing in hashed content reads the wall clock directly.

Timestamps are strings of the form YYYY-MM-DDTHH:MM:SSZ (UTC, second precision), so that
canonical JSON of a record is stable across platforms.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Clock(Protocol):
    def now(self) -> str:
        """Return the current time as a UTC timestamp string."""


def format_utc(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("naive datetime refused; supply a timezone")
    return moment.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_utc(text: str) -> datetime:
    """Parse a timestamp produced by format_utc, or raise ValueError."""
    if not isinstance(text, str):
        raise ValueError(f"timestamp must be a string, got {type(text).__name__}")
    moment = datetime.strptime(text, TIMESTAMP_FORMAT)
    return moment.replace(tzinfo=timezone.utc)


class FixedClock:
    """Always returns the same instant. For tests and reproducible demos."""

    def __init__(self, at: str) -> None:
        parse_utc(at)
        self._at = at

    def now(self) -> str:
        return self._at


class StepClock:
    """Returns start, then start plus step, then plus two steps. Deterministic ordering."""

    def __init__(self, start: str = "2026-01-01T00:00:00Z", step_seconds: int = 1) -> None:
        self._next = parse_utc(start)
        self._step = timedelta(seconds=step_seconds)

    def now(self) -> str:
        current = self._next
        self._next = current + self._step
        return format_utc(current)


class SystemClock:
    """Wall clock. Only the CLI uses it, and only when no --at is given."""

    def now(self) -> str:
        return format_utc(datetime.now(timezone.utc))
