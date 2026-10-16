import json

import pytest

from src.config import (
    ConfigError,
    DetectionConfig,
    config_from_dict,
    load_config,
    with_threshold,
)


def test_bundled_config_loads_and_matches_defaults():
    assert load_config() == DetectionConfig()


def test_partial_config_uses_defaults_for_the_rest():
    config = config_from_dict({"failed_login_by_ip": {"threshold": 9}})
    assert config.failed_by_ip_threshold == 9
    assert config.failed_by_user_threshold == DetectionConfig().failed_by_user_threshold


def test_business_hours_section():
    config = config_from_dict({"business_hours": {"start_hour": 9, "end_hour": 17,
                                                  "business_days": [0, 1], "utc_offset_hours": 3}})
    assert (config.business_hours_start, config.business_hours_end) == (9, 17)
    assert config.business_days == (0, 1) and config.utc_offset_hours == 3


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"unknown_rule": {}},
        {"failed_login_by_ip": {"treshold": 5}},  # typo
        {"failed_login_by_ip": {"threshold": 0}},
        {"failed_login_by_ip": {"threshold": "5"}},
        {"failed_login_by_ip": {"threshold": True}},
        {"failed_login_by_ip": {"window_minutes": -1}},
        {"business_hours": {"start_hour": 18, "end_hour": 8}},
        {"business_hours": {"end_hour": 25}},
        {"business_hours": {"business_days": []}},
        {"business_hours": {"business_days": [7]}},
        {"business_hours": {"utc_offset_hours": 40}},
    ],
)
def test_invalid_configs_are_rejected(data):
    with pytest.raises(ConfigError):
        config_from_dict(data)


def test_explicit_missing_file_and_bad_json(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(bad)


def test_with_threshold_overrides_rules_one_and_two_only():
    config = with_threshold(DetectionConfig(), 8)
    assert config.failed_by_ip_threshold == config.failed_by_user_threshold == 8
    assert config.success_after_failures_threshold == 3
    with pytest.raises(ConfigError):
        with_threshold(DetectionConfig(), 0)
