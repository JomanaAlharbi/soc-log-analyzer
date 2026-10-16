"""Read and validate authentication logs from CSV files.

This module only *parses*. It knows nothing about detection rules or reports.

Expected columns (header names are case-insensitive; extra columns are ignored):

    timestamp   ISO 8601, e.g. 2026-03-02T09:15:00Z or 2026-03-02 09:15:00+01:00
                (timestamps without a timezone are assumed to be UTC)
    username    non-empty text
    source_ip   IPv4 or IPv6 address
    event_type  login_success | login_failure (a few aliases are accepted)

Lines starting with '#' *before the header* are treated as comments.
"""

from __future__ import annotations

import csv
import ipaddress
import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

REQUIRED_COLUMNS = ("timestamp", "username", "source_ip", "event_type")
MAX_USERNAME_LENGTH = 128

SUCCESS = "success"
FAILURE = "failure"
_EVENT_TYPE_ALIASES = {
    "login_success": SUCCESS,
    "success": SUCCESS,
    "successful": SUCCESS,
    "accepted": SUCCESS,
    "login_failure": FAILURE,
    "failure": FAILURE,
    "failed": FAILURE,
    "fail": FAILURE,
    "login_failed": FAILURE,
}

# Reserved for documentation (RFC 5737 / RFC 3849); used for synthetic sample data.
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


class LogFormatError(Exception):
    """The file as a whole cannot be analysed (missing, empty, wrong columns...)."""


@dataclass(frozen=True)
class LogEvent:
    """One valid authentication event. Timestamps are always timezone-aware UTC."""

    line_number: int
    timestamp: datetime
    username: str
    source_ip: str
    event_type: str  # "success" or "failure"
    ip_category: str

    @property
    def is_failure(self) -> bool:
        return self.event_type == FAILURE

    @property
    def is_success(self) -> bool:
        return self.event_type == SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "timestamp": self.timestamp.isoformat(),
            "username": self.username,
            "source_ip": self.source_ip,
            "ip_category": self.ip_category,
            "event_type": self.event_type,
        }


@dataclass(frozen=True)
class RowError:
    """A single malformed row that was skipped."""

    line_number: int
    message: str


@dataclass
class ParseResult:
    events: list[LogEvent] = field(default_factory=list)
    errors: list[RowError] = field(default_factory=list)
    total_rows: int = 0  # non-blank data rows read (valid + malformed)


class _RowProblem(Exception):
    """Internal: a row-level validation failure with a human-readable reason."""


def _show(value: str) -> str:
    """Safely display untrusted text (escapes control and non-ASCII characters)."""
    shortened = value if len(value) <= 60 else value[:60] + "..."
    return ascii(shortened)


def classify_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Describe the kind of address. This says nothing about reputation or intent.

    Returns one of: documentation, loopback, link_local, multicast, reserved,
    private, public.
    """
    for network in _DOCUMENTATION_NETWORKS:
        if address.version == network.version and address in network:
            return "documentation"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified or address.is_reserved:
        return "reserved"
    if address.is_private:
        return "private"
    if address.is_global:
        return "public"
    return "reserved"  # e.g. shared address space 100.64.0.0/10


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp and return it as timezone-aware UTC.

    Naive timestamps are assumed to already be UTC. Raises ValueError if invalid.
    """
    text = value.strip()
    if ":" not in text:
        raise ValueError("a time of day is required")
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except OverflowError as exc:  # extreme dates cannot be converted to UTC
        raise ValueError("timestamp is out of the supported range") from exc


def normalize_event_type(value: str) -> str:
    key = value.strip().lower()
    if key not in _EVENT_TYPE_ALIASES:
        raise ValueError(f"unknown event type {_show(value)}")
    return _EVENT_TYPE_ALIASES[key]


def _build_event(line_number: int, fields: dict[str, str]) -> LogEvent:
    missing = [name for name in REQUIRED_COLUMNS if not fields[name]]
    if missing:
        raise _RowProblem(f"missing value(s) for: {', '.join(missing)}")
    try:
        timestamp = parse_timestamp(fields["timestamp"])
    except ValueError:
        raise _RowProblem(
            f"invalid timestamp {_show(fields['timestamp'])} "
            "(expected ISO 8601, e.g. 2026-03-02T09:15:00Z)"
        ) from None
    try:
        address = ipaddress.ip_address(fields["source_ip"])
    except ValueError:
        raise _RowProblem(
            f"invalid IP address {_show(fields['source_ip'])}"
        ) from None
    try:
        event_type = normalize_event_type(fields["event_type"])
    except ValueError as exc:
        raise _RowProblem(
            f"{exc} (expected login_success or login_failure)"
        ) from None
    username = fields["username"]
    if len(username) > MAX_USERNAME_LENGTH:
        raise _RowProblem(f"username longer than {MAX_USERNAME_LENGTH} characters")
    return LogEvent(
        line_number=line_number,
        timestamp=timestamp,
        username=username,
        source_ip=str(address),
        event_type=event_type,
        ip_category=classify_ip(address),
    )


def parse_csv_stream(handle: TextIO) -> ParseResult:
    """Parse an open text stream. Malformed rows are collected, not fatal."""
    skipped_lines = 0
    first_line = None
    for line in handle:
        if not line.strip() or line.lstrip().startswith("#"):
            skipped_lines += 1
            continue
        first_line = line
        break
    if first_line is None:
        raise LogFormatError("The input file is empty: no header row was found.")

    reader = csv.reader(itertools.chain([first_line], handle))
    header = next(reader)
    columns = [c.strip().lower() for c in header]
    missing = [c for c in REQUIRED_COLUMNS if c not in columns]
    if missing:
        raise LogFormatError(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Found: {', '.join(columns)}. "
            f"Required: {', '.join(REQUIRED_COLUMNS)}."
        )
    index = {name: columns.index(name) for name in REQUIRED_COLUMNS}

    result = ParseResult()
    for row in reader:
        if not row or all(not cell.strip() for cell in row):
            continue  # blank line
        result.total_rows += 1
        line_number = reader.line_num + skipped_lines
        if len(row) > len(columns):
            result.errors.append(
                RowError(
                    line_number,
                    f"Line {line_number}: expected at most {len(columns)} fields "
                    f"but found {len(row)}",
                )
            )
            continue
        padded = row + [""] * (len(columns) - len(row))
        fields = {name: padded[i].strip() for name, i in index.items()}
        try:
            result.events.append(_build_event(line_number, fields))
        except _RowProblem as problem:
            result.errors.append(RowError(line_number, f"Line {line_number}: {problem}"))
    return result


def parse_log_file(path: str | Path) -> ParseResult:
    """Read a CSV authentication log (read-only). Raises LogFormatError for
    problems that make the whole file unusable."""
    file_path = Path(path)
    if not file_path.is_file():
        raise LogFormatError(f"Input file not found (or not a file): {file_path}")
    try:
        with file_path.open("r", encoding="utf-8-sig", newline="") as handle:
            return parse_csv_stream(handle)
    except UnicodeDecodeError:
        raise LogFormatError("The input file is not valid UTF-8 text.") from None
    except csv.Error as exc:
        raise LogFormatError(f"The input file is not valid CSV: {exc}") from exc
    except OSError as exc:
        raise LogFormatError(f"Could not read the input file: {exc}") from exc
