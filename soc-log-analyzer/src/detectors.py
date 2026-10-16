"""Detection rules. Pure functions: events + config in, alerts out.

Nothing here reads files, writes reports, or touches the network.
Alerts describe *suspicious patterns that deserve review*; they never prove an
attack or a compromise.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Any, Callable, Hashable, Sequence

from .config import DetectionConfig
from .log_parser import LogEvent

RULE_FAILED_BY_IP = "failed_logins_by_ip"
RULE_FAILED_BY_USER = "failed_logins_by_user"
RULE_SUCCESS_AFTER_FAILURES = "success_after_failures"
RULE_OFF_HOURS = "off_hours_activity"
RULE_MULTIPLE_ACCOUNTS = "multiple_accounts_from_ip"

RULE_NAMES = {
    RULE_FAILED_BY_IP: "Repeated failed logins from one IP address",
    RULE_FAILED_BY_USER: "Repeated failed logins against one username",
    RULE_SUCCESS_AFTER_FAILURES: "Successful login after multiple failures",
    RULE_OFF_HOURS: "Authentication activity outside business hours",
    RULE_MULTIPLE_ACCOUNTS: "Multiple accounts targeted from one IP address",
}

RECOMMENDED_ACTIONS: dict[str, list[str]] = {
    RULE_FAILED_BY_IP: [
        "Check authentication logs on other systems for the same source IP.",
        "Confirm the IP is not a legitimate shared address (office NAT, VPN, scanner, misconfigured script).",
        "If unauthorized, consider rate limiting or temporarily blocking the IP at the firewall.",
        "Verify that account lockout or login throttling is enabled.",
    ],
    RULE_FAILED_BY_USER: [
        "Contact the account owner to check whether they were locking themselves out.",
        "Check whether any login for this account succeeded around the same time.",
        "Enforce multi-factor authentication (MFA) for the account.",
        "Review the account lockout policy.",
    ],
    RULE_SUCCESS_AFTER_FAILURES: [
        "Contact the account owner to confirm the successful login was theirs.",
        "If not confirmed, reset the password and revoke active sessions.",
        "Review what the account accessed after the successful login.",
        "Enforce multi-factor authentication (MFA) for the account.",
    ],
    RULE_OFF_HOURS: [
        "Confirm with the user or their manager whether the activity was expected (on-call, travel, time zones).",
        "Check whether the account normally authenticates at these times.",
        "Review related activity for the same account around the same time.",
    ],
    RULE_MULTIPLE_ACCOUNTS: [
        "Review all failed logins from the source IP, as this pattern is typical of password spraying.",
        "Check whether any targeted account had a successful login from the same IP.",
        "Consider blocking or rate limiting the IP once confirmed unauthorized.",
        "Enforce MFA and review password policy for the targeted accounts.",
    ],
}

_DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def escalate(self) -> "Severity":
        """One level higher, capped at CRITICAL."""
        return Severity(min(int(self) + 1, int(Severity.CRITICAL)))


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: Severity
    subject: str  # the IP address or username the alert is about
    first_seen: datetime
    last_seen: datetime
    explanation: str
    events: list[LogEvent]
    recommended_actions: list[str]
    alert_id: str = ""

    @property
    def event_count(self) -> int:
        return len(self.events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "severity": self.severity.name,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "subject": self.subject,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "explanation": self.explanation,
            "recommended_actions": list(self.recommended_actions),
            "events": [e.to_dict() for e in self.events],
        }


# --------------------------------------------------------------------------
# Severity rules (documented in docs/detection_rules.md)
# --------------------------------------------------------------------------
def severity_for_count(count: int, threshold: int) -> Severity:
    """Severity for volume-based rules (1, 2 and 5).

    below threshold -> LOW (informational; such alerts are not generated)
    threshold       -> MEDIUM
    2 x threshold   -> HIGH
    Volume alone never produces CRITICAL.
    """
    if count < threshold:
        return Severity.LOW
    if count >= 2 * threshold:
        return Severity.HIGH
    return Severity.MEDIUM


def classify_success_after_failures(
    failure_count: int, threshold: int, success_outside_business_hours: bool
) -> Severity:
    """Severity for rule 3: HIGH by default; CRITICAL when failures reach
    2 x threshold or the successful login happened outside business hours."""
    if failure_count >= 2 * threshold or success_outside_business_hours:
        return Severity.CRITICAL
    return Severity.HIGH


def classify_off_hours(events: Sequence[LogEvent]) -> Severity:
    """Rule 4: LOW, or MEDIUM when any failed login is among the events."""
    return Severity.MEDIUM if any(e.is_failure for e in events) else Severity.LOW


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _sorted(events: Sequence[LogEvent]) -> list[LogEvent]:
    return sorted(events, key=lambda e: (e.timestamp, e.line_number))


def _group_by(
    events: Sequence[LogEvent], key: Callable[[LogEvent], Hashable]
) -> dict[Hashable, list[LogEvent]]:
    groups: dict[Hashable, list[LogEvent]] = {}
    for event in events:
        groups.setdefault(key(event), []).append(event)
    return groups


def _user_key(event: LogEvent) -> str:
    return event.username.casefold()  # usernames are compared case-insensitively


def _find_clusters(
    events: Sequence[LogEvent],
    window: timedelta,
    is_hit: Callable[[Sequence[LogEvent]], bool],
) -> list[list[LogEvent]]:
    """Slide a time window over time-sorted events.

    Starting at each event, take every event within `window` (inclusive). If
    `is_hit` accepts that group, report it and continue *after* it, so one burst
    produces one alert instead of many overlapping ones.
    """
    clusters: list[list[LogEvent]] = []
    start, total = 0, len(events)
    while start < total:
        end = start
        while (
            end + 1 < total
            and events[end + 1].timestamp - events[start].timestamp <= window
        ):
            end += 1
        candidate = list(events[start : end + 1])
        if is_hit(candidate):
            clusters.append(candidate)
            start = end + 1
        else:
            start += 1
    return clusters


def _summarize(items: Sequence[str], limit: int = 5) -> str:
    unique = sorted(set(items))
    shown = ", ".join(unique[:limit])
    if len(unique) > limit:
        shown += f" and {len(unique) - limit} more"
    return shown


def _make_alert(
    rule_id: str,
    severity: Severity,
    subject: str,
    events: Sequence[LogEvent],
    explanation: str,
) -> Alert:
    ordered = _sorted(events)
    return Alert(
        rule_id=rule_id,
        rule_name=RULE_NAMES[rule_id],
        severity=severity,
        subject=subject,
        first_seen=ordered[0].timestamp,
        last_seen=ordered[-1].timestamp,
        explanation=explanation,
        events=ordered,
        recommended_actions=list(RECOMMENDED_ACTIONS[rule_id]),
    )


def is_outside_business_hours(timestamp: datetime, config: DetectionConfig) -> bool:
    """True if the (UTC) timestamp falls outside the configured business hours,
    after converting to the configured local offset."""
    local = timestamp.astimezone(timezone(timedelta(hours=config.utc_offset_hours)))
    if local.weekday() not in config.business_days:
        return True
    return not (config.business_hours_start <= local.hour < config.business_hours_end)


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
def detect_failed_logins_by_ip(
    events: Sequence[LogEvent], config: DetectionConfig
) -> list[Alert]:
    """Rule 1: N or more failed logins from one IP within the window."""
    threshold = config.failed_by_ip_threshold
    window = timedelta(minutes=config.failed_by_ip_window_minutes)
    failures = [e for e in _sorted(events) if e.is_failure]
    alerts: list[Alert] = []
    for ip, group in _group_by(failures, lambda e: e.source_ip).items():
        for cluster in _find_clusters(group, window, lambda c: len(c) >= threshold):
            users = _summarize([e.username for e in cluster])
            explanation = (
                f"{len(cluster)} failed login attempts came from {ip} "
                f"({cluster[0].ip_category} address) within "
                f"{config.failed_by_ip_window_minutes} minutes "
                f"(threshold: {threshold}). Username(s) tried: {users}. "
                "This is consistent with password guessing, but can also come from "
                "a misconfigured script or a shared NAT/VPN address. "
                "It does not show that any account was compromised."
            )
            alerts.append(
                _make_alert(
                    RULE_FAILED_BY_IP,
                    severity_for_count(len(cluster), threshold),
                    str(ip),
                    cluster,
                    explanation,
                )
            )
    return alerts


def detect_failed_logins_by_user(
    events: Sequence[LogEvent], config: DetectionConfig
) -> list[Alert]:
    """Rule 2: N or more failed logins against one username within the window."""
    threshold = config.failed_by_user_threshold
    window = timedelta(minutes=config.failed_by_user_window_minutes)
    failures = [e for e in _sorted(events) if e.is_failure]
    alerts: list[Alert] = []
    for group in _group_by(failures, _user_key).values():
        for cluster in _find_clusters(group, window, lambda c: len(c) >= threshold):
            username = cluster[0].username
            ips = _summarize([e.source_ip for e in cluster])
            explanation = (
                f"{len(cluster)} failed login attempts targeted the username "
                f"'{username}' within {config.failed_by_user_window_minutes} minutes "
                f"(threshold: {threshold}). Source IP(s): {ips}. "
                "This can indicate password guessing against this account, or a "
                "legitimate user who forgot their password. "
                "It does not show that the account was compromised."
            )
            alerts.append(
                _make_alert(
                    RULE_FAILED_BY_USER,
                    severity_for_count(len(cluster), threshold),
                    username,
                    cluster,
                    explanation,
                )
            )
    return alerts


def detect_success_after_failures(
    events: Sequence[LogEvent], config: DetectionConfig
) -> list[Alert]:
    """Rule 3: a successful login preceded by N or more failures for the same
    username within the window. A success resets the failure count."""
    threshold = config.success_after_failures_threshold
    window = timedelta(minutes=config.success_after_failures_window_minutes)
    alerts: list[Alert] = []
    for group in _group_by(_sorted(events), _user_key).values():
        failures: list[LogEvent] = []
        for event in group:
            if event.is_failure:
                failures.append(event)
                continue
            recent = [f for f in failures if event.timestamp - f.timestamp <= window]
            failures = []  # any success ends the failure sequence
            if len(recent) < threshold:
                continue
            off_hours = is_outside_business_hours(event.timestamp, config)
            severity = classify_success_after_failures(len(recent), threshold, off_hours)
            failure_ips = _summarize([f.source_ip for f in recent])
            same_ip = {f.source_ip for f in recent} == {event.source_ip}
            ip_note = (
                "from the same IP address"
                if same_ip
                else f"from {event.source_ip} (failures came from {failure_ips})"
            )
            explanation = (
                f"A successful login for '{event.username}' {ip_note} followed "
                f"{len(recent)} failed attempts within "
                f"{config.success_after_failures_window_minutes} minutes "
                f"(threshold: {threshold})."
                + (" The successful login was outside business hours." if off_hours else "")
                + " This sequence can mean a password was guessed, but it can equally "
                "be a legitimate user who mistyped their password. Verify with the "
                "account owner before drawing conclusions."
            )
            alerts.append(
                _make_alert(
                    RULE_SUCCESS_AFTER_FAILURES,
                    severity,
                    event.username,
                    recent + [event],
                    explanation,
                )
            )
    return alerts


def detect_off_hours_activity(
    events: Sequence[LogEvent], config: DetectionConfig
) -> list[Alert]:
    """Rule 4: authentication events outside business hours, grouped into one
    alert per username per local calendar day."""
    tz = timezone(timedelta(hours=config.utc_offset_hours))
    off_hours = [e for e in _sorted(events) if is_outside_business_hours(e.timestamp, config)]
    groups = _group_by(
        off_hours, lambda e: (_user_key(e), e.timestamp.astimezone(tz).date())
    )
    days = "/".join(_DAY_NAMES[d] for d in sorted(config.business_days))
    alerts: list[Alert] = []
    for (_, day), group in groups.items():
        successes = sum(1 for e in group if e.is_success)
        failures = len(group) - successes
        username = group[0].username
        explanation = (
            f"{len(group)} authentication event(s) for '{username}' on {day.isoformat()} "
            f"({successes} successful, {failures} failed) fell outside the configured "
            f"business hours ({config.business_hours_start:02d}:00-"
            f"{config.business_hours_end:02d}:00, {days}, UTC{config.utc_offset_hours:+g}). "
            "Off-hours activity is often legitimate (on-call work, travel, other time "
            "zones) and is only a prompt to check."
        )
        alerts.append(
            _make_alert(RULE_OFF_HOURS, classify_off_hours(group), username, group, explanation)
        )
    return alerts


def detect_multiple_accounts_from_ip(
    events: Sequence[LogEvent], config: DetectionConfig
) -> list[Alert]:
    """Rule 5: failed logins against N or more *different* usernames from one IP
    within the window (a pattern often called password spraying)."""
    threshold = config.multi_account_threshold
    window = timedelta(minutes=config.multi_account_window_minutes)

    def enough_accounts(cluster: Sequence[LogEvent]) -> bool:
        return len({_user_key(e) for e in cluster}) >= threshold

    failures = [e for e in _sorted(events) if e.is_failure]
    alerts: list[Alert] = []
    for ip, group in _group_by(failures, lambda e: e.source_ip).items():
        for cluster in _find_clusters(group, window, enough_accounts):
            distinct = len({_user_key(e) for e in cluster})
            explanation = (
                f"Failed logins from {ip} ({cluster[0].ip_category} address) targeted "
                f"{distinct} different accounts within "
                f"{config.multi_account_window_minutes} minutes (threshold: {threshold}). "
                f"Accounts: {_summarize([e.username for e in cluster])}. "
                "Trying a few passwords across many accounts is a common way to avoid "
                "lockouts, but a shared gateway or a mis-configured service can look "
                "the same. It does not show that any account was compromised."
            )
            alerts.append(
                _make_alert(
                    RULE_MULTIPLE_ACCOUNTS,
                    severity_for_count(distinct, threshold),
                    str(ip),
                    cluster,
                    explanation,
                )
            )
    return alerts


def run_all_detectors(
    events: Sequence[LogEvent], config: DetectionConfig
) -> list[Alert]:
    """Run every rule, sort alerts by time, and assign stable IDs."""
    alerts: list[Alert] = []
    for detector in (
        detect_failed_logins_by_ip,
        detect_failed_logins_by_user,
        detect_success_after_failures,
        detect_off_hours_activity,
        detect_multiple_accounts_from_ip,
    ):
        alerts.extend(detector(events, config))
    alerts.sort(key=lambda a: (a.first_seen, a.rule_id, a.subject))
    for number, alert in enumerate(alerts, start=1):
        alert.alert_id = f"ALERT-{number:04d}"
    return alerts
