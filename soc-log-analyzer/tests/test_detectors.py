from datetime import datetime, timezone

import pytest

from src.config import DetectionConfig
from src.detectors import (
    RULE_FAILED_BY_IP,
    RULE_FAILED_BY_USER,
    RULE_MULTIPLE_ACCOUNTS,
    RULE_OFF_HOURS,
    RULE_SUCCESS_AFTER_FAILURES,
    Severity,
    classify_off_hours,
    classify_success_after_failures,
    detect_failed_logins_by_ip,
    detect_failed_logins_by_user,
    detect_multiple_accounts_from_ip,
    detect_off_hours_activity,
    detect_success_after_failures,
    is_outside_business_hours,
    run_all_detectors,
    severity_for_count,
)
from src.log_parser import FAILURE, SUCCESS

CONFIG = DetectionConfig()  # defaults: thresholds 5/5/3/3, windows 10/10/15/10 minutes


# ------------------------------------------------------------ rule 1 (by IP)
def failures_from_ip(make_event, count, spacing=10, ip="192.0.2.10"):
    return [make_event(i * spacing, username=f"user{i}", ip=ip) for i in range(count)]


def test_failed_by_ip_below_threshold_no_alert(make_event):
    events = failures_from_ip(make_event, CONFIG.failed_by_ip_threshold - 1)
    assert detect_failed_logins_by_ip(events, CONFIG) == []


def test_failed_by_ip_at_threshold_alerts(make_event):
    events = failures_from_ip(make_event, CONFIG.failed_by_ip_threshold)
    alerts = detect_failed_logins_by_ip(events, CONFIG)
    assert len(alerts) == 1
    assert alerts[0].rule_id == RULE_FAILED_BY_IP
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].subject == "192.0.2.10"
    assert "does not show" in alerts[0].explanation  # no attack-proof claims


def test_failed_by_ip_window_boundary_is_inclusive(make_event):
    window = CONFIG.failed_by_ip_window_minutes * 60
    # five failures; first and last exactly `window` seconds apart -> alert
    inside = [make_event(t) for t in (0, 100, 200, 300, window)]
    assert len(detect_failed_logins_by_ip(inside, CONFIG)) == 1
    # one second too late -> no alert
    outside = [make_event(t) for t in (0, 100, 200, 300, window + 1)]
    assert detect_failed_logins_by_ip(outside, CONFIG) == []


def test_failed_by_ip_ignores_successes_and_other_ips(make_event):
    events = [make_event(i, kind=SUCCESS) for i in range(10)]
    events += failures_from_ip(make_event, 3, ip="192.0.2.20")
    events += failures_from_ip(make_event, 3, ip="192.0.2.21")
    assert detect_failed_logins_by_ip(events, CONFIG) == []


def test_failed_by_ip_high_severity_at_double_threshold(make_event):
    events = failures_from_ip(make_event, CONFIG.failed_by_ip_threshold * 2, spacing=5)
    assert detect_failed_logins_by_ip(events, CONFIG)[0].severity == Severity.HIGH


def test_burst_produces_single_alert_not_overlapping_ones(make_event):
    events = failures_from_ip(make_event, 8, spacing=5)
    assert len(detect_failed_logins_by_ip(events, CONFIG)) == 1


def test_two_separate_bursts_produce_two_alerts(make_event):
    first = failures_from_ip(make_event, 5, spacing=5)
    second = [make_event(3600 + i * 5, username=f"u{i}") for i in range(5)]
    assert len(detect_failed_logins_by_ip(first + second, CONFIG)) == 2


def test_custom_threshold_is_respected(make_event):
    config = DetectionConfig(failed_by_ip_threshold=2)
    assert len(detect_failed_logins_by_ip(failures_from_ip(make_event, 2), config)) == 1


# ---------------------------------------------------------- rule 2 (by user)
def test_failed_by_user_threshold_boundary(make_event):
    t = CONFIG.failed_by_user_threshold
    below = [make_event(i * 10, username="alice", ip=f"192.0.2.{i + 1}") for i in range(t - 1)]
    assert detect_failed_logins_by_user(below, CONFIG) == []
    at = [make_event(i * 10, username="alice", ip=f"192.0.2.{i + 1}") for i in range(t)]
    alerts = detect_failed_logins_by_user(at, CONFIG)
    assert len(alerts) == 1 and alerts[0].rule_id == RULE_FAILED_BY_USER


def test_failed_by_user_is_case_insensitive(make_event):
    events = [make_event(i * 10, username="Alice" if i % 2 else "alice") for i in range(5)]
    assert len(detect_failed_logins_by_user(events, CONFIG)) == 1


# ---------------------------------------------------- rule 3 (success after)
def test_success_after_failures_alert(make_event):
    events = [make_event(i * 20, username="bob") for i in range(3)]
    events.append(make_event(90, username="bob", kind=SUCCESS))
    alerts = detect_success_after_failures(events, CONFIG)
    assert len(alerts) == 1
    assert alerts[0].rule_id == RULE_SUCCESS_AFTER_FAILURES
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].event_count == 4
    assert "mistyped" in alerts[0].explanation  # neutral, not an accusation


def test_success_after_too_few_failures_no_alert(make_event):
    events = [make_event(i * 20, username="bob") for i in range(2)]
    events.append(make_event(90, username="bob", kind=SUCCESS))
    assert detect_success_after_failures(events, CONFIG) == []


def test_failures_outside_window_do_not_count(make_event):
    window = CONFIG.success_after_failures_window_minutes * 60
    failures = [make_event(i, username="bob") for i in range(3)]
    late_success = make_event(2 + window + 1, username="bob", kind=SUCCESS)
    assert detect_success_after_failures(failures + [late_success], CONFIG) == []
    on_edge = make_event(0 + window, username="bob", kind=SUCCESS)  # oldest failure exactly at window
    assert len(detect_success_after_failures(failures + [on_edge], CONFIG)) == 1


def test_earlier_success_resets_failure_sequence(make_event):
    events = [
        make_event(0, username="bob"),
        make_event(10, username="bob"),
        make_event(20, username="bob", kind=SUCCESS),  # resets the count
        make_event(30, username="bob"),
        make_event(40, username="bob", kind=SUCCESS),
    ]
    assert detect_success_after_failures(events, CONFIG) == []


def test_success_after_failures_is_per_username(make_event):
    events = [make_event(i, username="bob") for i in range(3)]
    events.append(make_event(10, username="carol", kind=SUCCESS))
    assert detect_success_after_failures(events, CONFIG) == []


# ----------------------------------------------------- severity classification
@pytest.mark.parametrize(
    "count, threshold, expected",
    [
        (4, 5, Severity.LOW),
        (5, 5, Severity.MEDIUM),
        (9, 5, Severity.MEDIUM),
        (10, 5, Severity.HIGH),
        (500, 5, Severity.HIGH),  # volume alone never reaches CRITICAL
    ],
)
def test_severity_for_count(count, threshold, expected):
    assert severity_for_count(count, threshold) == expected


@pytest.mark.parametrize(
    "failures, off_hours, expected",
    [
        (3, False, Severity.HIGH),
        (5, False, Severity.HIGH),
        (6, False, Severity.CRITICAL),
        (3, True, Severity.CRITICAL),
    ],
)
def test_classify_success_after_failures(failures, off_hours, expected):
    assert classify_success_after_failures(failures, 3, off_hours) == expected


def test_off_hours_severity(make_event):
    assert classify_off_hours([make_event(kind=SUCCESS)]) == Severity.LOW
    assert classify_off_hours([make_event(kind=SUCCESS), make_event(kind=FAILURE)]) == Severity.MEDIUM


def test_severity_escalate_is_capped():
    assert Severity.LOW.escalate() == Severity.MEDIUM
    assert Severity.CRITICAL.escalate() == Severity.CRITICAL


# ------------------------------------------------------- rule 4 (off hours)
@pytest.mark.parametrize(
    "stamp, expected",
    [
        (datetime(2026, 3, 2, 8, 0, tzinfo=timezone.utc), False),    # Monday 08:00 (start inclusive)
        (datetime(2026, 3, 2, 7, 59, tzinfo=timezone.utc), True),
        (datetime(2026, 3, 2, 17, 59, tzinfo=timezone.utc), False),
        (datetime(2026, 3, 2, 18, 0, tzinfo=timezone.utc), True),    # end exclusive
        (datetime(2026, 3, 7, 10, 0, tzinfo=timezone.utc), True),    # Saturday
        (datetime(2026, 3, 8, 10, 0, tzinfo=timezone.utc), True),    # Sunday
    ],
)
def test_business_hours_boundaries(stamp, expected):
    assert is_outside_business_hours(stamp, CONFIG) is expected


def test_business_hours_respect_utc_offset():
    config = DetectionConfig(utc_offset_hours=2)
    # 06:30 UTC = 08:30 local -> inside; 16:30 UTC = 18:30 local -> outside
    assert not is_outside_business_hours(datetime(2026, 3, 2, 6, 30, tzinfo=timezone.utc), config)
    assert is_outside_business_hours(datetime(2026, 3, 2, 16, 30, tzinfo=timezone.utc), config)


def test_off_hours_one_alert_per_user_per_day(make_event, base_time):
    night = base_time.replace(hour=2)
    events = [
        make_event(0, username="alice", kind=SUCCESS, at=night),
        make_event(600, username="alice", kind=SUCCESS, at=night),
        make_event(0, username="bob", kind=SUCCESS, at=night),
        make_event(0, username="alice", kind=SUCCESS, at=base_time),  # business hours
    ]
    alerts = detect_off_hours_activity(events, CONFIG)
    assert sorted(a.subject for a in alerts) == ["alice", "bob"]
    assert all(a.rule_id == RULE_OFF_HOURS and a.severity == Severity.LOW for a in alerts)


def test_off_hours_not_triggered_in_business_hours(make_event):
    assert detect_off_hours_activity([make_event(kind=SUCCESS)], CONFIG) == []


# ----------------------------------------------- rule 5 (multiple accounts)
def spray(make_event, users, spacing=30, ip="192.0.2.99"):
    return [make_event(i * spacing, username=u, ip=ip) for i, u in enumerate(users)]


def test_multiple_accounts_threshold_boundary(make_event):
    assert detect_multiple_accounts_from_ip(spray(make_event, ["a", "b"]), CONFIG) == []
    alerts = detect_multiple_accounts_from_ip(spray(make_event, ["a", "b", "c"]), CONFIG)
    assert len(alerts) == 1
    assert alerts[0].rule_id == RULE_MULTIPLE_ACCOUNTS
    assert alerts[0].severity == Severity.MEDIUM


def test_multiple_accounts_counts_distinct_users_only(make_event):
    assert detect_multiple_accounts_from_ip(spray(make_event, ["a"] * 6), CONFIG) == []


def test_multiple_accounts_window_boundary(make_event):
    window = CONFIG.multi_account_window_minutes * 60
    ok = [make_event(0, username="a"), make_event(100, username="b"), make_event(window, username="c")]
    late = [make_event(0, username="a"), make_event(100, username="b"), make_event(window + 1, username="c")]
    assert len(detect_multiple_accounts_from_ip(ok, CONFIG)) == 1
    assert detect_multiple_accounts_from_ip(late, CONFIG) == []


def test_multiple_accounts_high_severity_at_double_threshold(make_event):
    users = [f"u{i}" for i in range(6)]
    assert detect_multiple_accounts_from_ip(spray(make_event, users), CONFIG)[0].severity == Severity.HIGH


# ------------------------------------------------------------- orchestration
def test_run_all_detectors_assigns_sequential_ids_in_time_order(make_event, base_time):
    events = failures_from_ip(make_event, 5)
    events += [make_event(i, username="bob", ip="192.0.2.50", at=base_time.replace(day=3)) for i in range(5)]
    alerts = run_all_detectors(events, CONFIG)
    assert [a.alert_id for a in alerts] == [f"ALERT-{i:04d}" for i in range(1, len(alerts) + 1)]
    assert [a.first_seen for a in alerts] == sorted(a.first_seen for a in alerts)


def test_no_events_means_no_alerts():
    assert run_all_detectors([], CONFIG) == []


def test_detection_is_deterministic(make_event):
    events = failures_from_ip(make_event, 7)
    first = [a.to_dict() for a in run_all_detectors(events, CONFIG)]
    second = [a.to_dict() for a in run_all_detectors(list(reversed(events)), CONFIG)]
    assert first == second  # input order does not matter
