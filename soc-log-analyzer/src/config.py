"""Detection configuration: defaults, loading from JSON, and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

# Resolved relative to the repository root, so it works from any working directory.
DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "detection_rules.json"
)

_POSITIVE_INT_FIELDS = (
    "failed_by_ip_threshold",
    "failed_by_ip_window_minutes",
    "failed_by_user_threshold",
    "failed_by_user_window_minutes",
    "success_after_failures_threshold",
    "success_after_failures_window_minutes",
    "multi_account_threshold",
    "multi_account_window_minutes",
)


class ConfigError(ValueError):
    """Raised when the configuration file is missing, unreadable, or invalid."""


@dataclass(frozen=True)
class DetectionConfig:
    """All tunable thresholds and time windows used by the detection rules."""

    # Rule 1: repeated failures from one IP address
    failed_by_ip_threshold: int = 5
    failed_by_ip_window_minutes: int = 10
    # Rule 2: repeated failures against one username
    failed_by_user_threshold: int = 5
    failed_by_user_window_minutes: int = 10
    # Rule 3: successful login after multiple failures
    success_after_failures_threshold: int = 3
    success_after_failures_window_minutes: int = 15
    # Rule 5: several accounts targeted from one IP address
    multi_account_threshold: int = 3
    multi_account_window_minutes: int = 10
    # Rule 4: business hours (local time = UTC + utc_offset_hours)
    business_hours_start: int = 8  # inclusive, 0-23
    business_hours_end: int = 18  # exclusive, 1-24
    business_days: tuple[int, ...] = (0, 1, 2, 3, 4)  # Monday=0 ... Sunday=6
    utc_offset_hours: float = 0

    def validate(self) -> None:
        """Raise ConfigError if any value is out of range or has the wrong type."""
        for name in _POSITIVE_INT_FIELDS:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ConfigError(
                    f"'{name}' must be a whole number >= 1 (got {value!r})."
                )
        start, end = self.business_hours_start, self.business_hours_end
        for name, value in (("business_hours_start", start), ("business_hours_end", end)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigError(f"'{name}' must be a whole number (got {value!r}).")
        if not (0 <= start <= 23) or not (1 <= end <= 24) or start >= end:
            raise ConfigError(
                "Business hours must satisfy 0 <= start_hour <= 23, "
                f"1 <= end_hour <= 24 and start_hour < end_hour (got {start}, {end})."
            )
        if not self.business_days or any(
            isinstance(d, bool) or not isinstance(d, int) or not 0 <= d <= 6
            for d in self.business_days
        ):
            raise ConfigError(
                "'business_days' must be a non-empty list of integers 0-6 "
                "(Monday=0 ... Sunday=6)."
            )
        offset = self.utc_offset_hours
        if (
            isinstance(offset, bool)
            or not isinstance(offset, (int, float))
            or not (-12 <= offset <= 14)
        ):
            raise ConfigError(
                f"'utc_offset_hours' must be a number between -12 and 14 (got {offset!r})."
            )


# JSON section name -> prefix of the matching DetectionConfig fields
_RULE_SECTIONS = {
    "failed_login_by_ip": "failed_by_ip",
    "failed_login_by_user": "failed_by_user",
    "success_after_failures": "success_after_failures",
    "multiple_accounts_from_ip": "multi_account",
}
_BUSINESS_HOURS_KEYS = {
    "start_hour": "business_hours_start",
    "end_hour": "business_hours_end",
    "business_days": "business_days",
    "utc_offset_hours": "utc_offset_hours",
}


def _section(data: dict[str, Any], name: str, allowed: set[str]) -> dict[str, Any]:
    body = data.get(name, {})
    if not isinstance(body, dict):
        raise ConfigError(f"Configuration section '{name}' must be a JSON object.")
    unknown = sorted(k for k in body if k not in allowed and not k.startswith("_"))
    if unknown:
        raise ConfigError(
            f"Unknown key(s) in section '{name}': {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(allowed))}."
        )
    return body


def config_from_dict(data: Any) -> DetectionConfig:
    """Build and validate a DetectionConfig from parsed JSON data."""
    if not isinstance(data, dict):
        raise ConfigError("The configuration file must contain a JSON object.")
    allowed_sections = set(_RULE_SECTIONS) | {"business_hours"}
    unknown = sorted(k for k in data if k not in allowed_sections and not k.startswith("_"))
    if unknown:
        raise ConfigError(f"Unknown configuration section(s): {', '.join(unknown)}.")

    values: dict[str, Any] = {}
    for section, prefix in _RULE_SECTIONS.items():
        body = _section(data, section, {"threshold", "window_minutes"})
        if "threshold" in body:
            values[f"{prefix}_threshold"] = body["threshold"]
        if "window_minutes" in body:
            values[f"{prefix}_window_minutes"] = body["window_minutes"]

    hours = _section(data, "business_hours", set(_BUSINESS_HOURS_KEYS))
    for json_key, field_name in _BUSINESS_HOURS_KEYS.items():
        if json_key in hours:
            value = hours[json_key]
            if json_key == "business_days":
                if not isinstance(value, list):
                    raise ConfigError("'business_days' must be a list of integers 0-6.")
                value = tuple(value)
            values[field_name] = value

    config = DetectionConfig(**values)
    config.validate()
    return config


def load_config(path: str | Path | None = None) -> DetectionConfig:
    """Load configuration from JSON.

    With no path, the bundled config/detection_rules.json is used when present,
    otherwise built-in defaults. An explicitly given path must exist.
    """
    if path is None:
        if not DEFAULT_CONFIG_PATH.is_file():
            return DetectionConfig()
        config_path = DEFAULT_CONFIG_PATH
    else:
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"Configuration file not found: {config_path}")
    try:
        data = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Configuration file is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read configuration file: {exc}") from exc
    return config_from_dict(data)


def with_threshold(config: DetectionConfig, threshold: int) -> DetectionConfig:
    """Return a copy with the failed-login thresholds (rules 1 and 2) overridden."""
    new_config = replace(
        config,
        failed_by_ip_threshold=threshold,
        failed_by_user_threshold=threshold,
    )
    new_config.validate()
    return new_config
