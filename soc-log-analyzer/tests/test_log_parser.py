import ipaddress
from datetime import timezone

import pytest

from src.log_parser import (
    LogFormatError,
    classify_ip,
    parse_log_file,
    parse_timestamp,
)
from conftest import HEADER


def test_valid_csv_is_parsed(write_csv):
    path = write_csv(
        HEADER
        + "2026-03-02T09:00:00Z,alice,192.0.2.10,login_success\n"
        + "2026-03-02T09:01:00Z,bob,192.0.2.11,login_failure\n"
    )
    result = parse_log_file(path)
    assert result.total_rows == 2
    assert result.errors == []
    assert [e.username for e in result.events] == ["alice", "bob"]
    assert result.events[0].is_success and result.events[1].is_failure
    assert result.events[0].timestamp.tzinfo == timezone.utc


def test_missing_columns_raise_clear_error(write_csv):
    path = write_csv("timestamp,username\n2026-03-02T09:00:00Z,alice\n")
    with pytest.raises(LogFormatError) as exc:
        parse_log_file(path)
    assert "source_ip" in str(exc.value) and "event_type" in str(exc.value)


def test_header_is_case_insensitive_and_extra_columns_ignored(write_csv):
    path = write_csv(
        "Timestamp, USERNAME ,Source_IP,Event_Type,note\n"
        "2026-03-02T09:00:00Z,alice,192.0.2.10,LOGIN_SUCCESS,hello\n"
    )
    result = parse_log_file(path)
    assert len(result.events) == 1 and not result.errors


def test_malformed_timestamp_is_reported_and_other_rows_survive(write_csv):
    path = write_csv(
        HEADER
        + "yesterday,alice,192.0.2.10,login_success\n"
        + "2026-03-02,alice,192.0.2.10,login_success\n"  # date without time
        + "2026-03-02T09:00:00Z,bob,192.0.2.11,login_failure\n"
    )
    result = parse_log_file(path)
    assert len(result.events) == 1
    assert len(result.errors) == 2
    assert all("invalid timestamp" in e.message for e in result.errors)
    assert result.errors[0].line_number == 2


def test_invalid_ip_addresses_are_rejected(write_csv):
    path = write_csv(
        HEADER
        + "2026-03-02T09:00:00Z,alice,999.1.1.1,login_failure\n"
        + "2026-03-02T09:00:00Z,alice,not-an-ip,login_failure\n"
        + "2026-03-02T09:00:00Z,alice,2001:db8::1,login_failure\n"
    )
    result = parse_log_file(path)
    assert len(result.events) == 1  # only the IPv6 documentation address is valid
    assert len(result.errors) == 2
    assert all("invalid IP address" in e.message for e in result.errors)


def test_missing_values_unknown_event_and_extra_fields(write_csv):
    path = write_csv(
        HEADER
        + "2026-03-02T09:00:00Z,,192.0.2.10,login_failure\n"
        + "2026-03-02T09:00:00Z,alice,,login_failure\n"
        + "2026-03-02T09:00:00Z,alice,192.0.2.10\n"  # too few fields
        + "2026-03-02T09:00:00Z,alice,192.0.2.10,login_maybe\n"
        + "2026-03-02T09:00:00Z,alice,192.0.2.10,login_failure,extra\n"
    )
    result = parse_log_file(path)
    assert result.events == []
    assert result.total_rows == 5 and len(result.errors) == 5


def test_completely_empty_file_raises(write_csv):
    with pytest.raises(LogFormatError, match="empty"):
        parse_log_file(write_csv(""))


def test_header_only_file_gives_zero_events(write_csv):
    result = parse_log_file(write_csv(HEADER))
    assert result.events == [] and result.errors == [] and result.total_rows == 0


def test_comment_lines_before_header_are_skipped_and_line_numbers_stay_physical(write_csv):
    path = write_csv("# synthetic\n# data\n" + HEADER + "bad,alice,192.0.2.10,login_failure\n")
    result = parse_log_file(path)
    assert result.errors[0].line_number == 4


def test_missing_file_raises():
    with pytest.raises(LogFormatError, match="not found"):
        parse_log_file("this/file/does/not/exist.csv")


def test_non_utf8_file_raises(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_bytes(b"timestamp,username\n\xff\xfe\x00bad")
    with pytest.raises(LogFormatError):
        parse_log_file(path)


def test_utf8_bom_header_is_accepted(write_csv):
    path = write_csv("\ufeff" + HEADER + "2026-03-02T09:00:00Z,alice,192.0.2.10,login_success\n")
    assert len(parse_log_file(path).events) == 1


def test_timestamps_are_normalised_to_utc():
    assert parse_timestamp("2026-03-02T10:00:00+01:00").isoformat() == "2026-03-02T09:00:00+00:00"
    assert parse_timestamp("2026-03-02 09:00:00").isoformat() == "2026-03-02T09:00:00+00:00"  # naive = UTC
    assert parse_timestamp("2026-03-02T09:00:00Z").utcoffset().total_seconds() == 0


@pytest.mark.parametrize(
    "address, expected",
    [
        ("192.0.2.1", "documentation"),
        ("198.51.100.7", "documentation"),
        ("203.0.113.9", "documentation"),
        ("2001:db8::5", "documentation"),
        ("10.1.2.3", "private"),
        ("192.168.0.9", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "reserved"),
        ("100.64.0.1", "reserved"),
        ("8.8.8.8", "public"),
    ],
)
def test_ip_classification(address, expected):
    assert classify_ip(ipaddress.ip_address(address)) == expected
