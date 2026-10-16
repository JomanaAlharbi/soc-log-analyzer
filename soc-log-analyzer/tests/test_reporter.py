import csv
import json
from datetime import datetime, timezone

from src.config import DetectionConfig
from src.detectors import run_all_detectors
from src.log_parser import FAILURE, SUCCESS, ParseResult, parse_log_file
from src.reporter import (
    CSV_COLUMNS,
    CSV_FILENAME,
    JSON_FILENAME,
    MARKDOWN_FILENAME,
    build_report,
    generate_reports,
)

CONFIG = DetectionConfig()
FIXED_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def make_result(make_event):
    events = [make_event(i * 10, username=f"user{i}", ip="192.0.2.10") for i in range(6)]
    events.append(make_event(100, username="user0", ip="10.0.0.5", kind=SUCCESS))
    return ParseResult(events=events, errors=[], total_rows=len(events))


def test_summary_counts_and_metadata(make_event):
    result = make_result(make_event)
    alerts = run_all_detectors(result.events, CONFIG)
    report = build_report(result, alerts, input_file="/some/dir/auth.csv", config=CONFIG, analysis_time=FIXED_TIME)
    summary, meta = report["summary"], report["report_metadata"]
    assert summary["total_events"] == 7
    assert summary["failed_logins"] == 6 and summary["successful_logins"] == 1
    assert summary["total_alerts"] == len(alerts) == sum(summary["alerts_by_severity"].values())
    assert set(summary["alerts_by_severity"]) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert meta["input_file"] == "auth.csv"  # filename only, no directory path leaked
    assert meta["analysis_timestamp"] == "2026-01-15T12:00:00+00:00"
    assert "do not prove" in meta["disclaimer"]


def test_generate_reports_writes_three_valid_files(make_event, tmp_path):
    result = make_result(make_event)
    alerts = run_all_detectors(result.events, CONFIG)
    out = tmp_path / "nested" / "reports"  # created automatically
    paths = generate_reports(result, alerts, input_file="auth.csv", output_dir=out,
                             config=CONFIG, analysis_time=FIXED_TIME)
    assert paths["json"].name == JSON_FILENAME and paths["csv"].name == CSV_FILENAME
    assert paths["markdown"].name == MARKDOWN_FILENAME

    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["alerts"] and data["alerts"][0]["events"] and data["alerts"][0]["recommended_actions"]

    with paths["csv"].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert tuple(rows[0].keys()) == CSV_COLUMNS
    assert len(rows) == len(alerts)
    assert rows[0]["input_file"] == "auth.csv"
    assert rows[0]["analysis_timestamp"] == "2026-01-15T12:00:00+00:00"

    markdown = paths["markdown"].read_text(encoding="utf-8")
    for expected in ("auth.csv", "2026-01-15T12:00:00+00:00", "Total events analysed",
                     "Alerts by severity", "Recommended defensive actions", "Why this alert was generated"):
        assert expected in markdown


def test_report_for_empty_log(write_csv, tmp_path):
    result = parse_log_file(write_csv("timestamp,username,source_ip,event_type\n"))
    paths = generate_reports(result, [], input_file="empty.csv", output_dir=tmp_path,
                             config=CONFIG, analysis_time=FIXED_TIME)
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["summary"]["total_events"] == 0 and data["alerts"] == []
    assert "No alerts were generated" in paths["markdown"].read_text(encoding="utf-8")
    assert len(paths["csv"].read_text(encoding="utf-8").splitlines()) == 1  # header only


def test_csv_neutralises_formula_injection(make_event, tmp_path):
    events = [make_event(i * 5, username="=HYPERLINK(\"http://x\")", ip="192.0.2.77") for i in range(5)]
    alerts = run_all_detectors(events, CONFIG)
    paths = generate_reports(ParseResult(events=events, total_rows=5), alerts, input_file="x.csv",
                             output_dir=tmp_path, config=CONFIG, analysis_time=FIXED_TIME)
    with paths["csv"].open(encoding="utf-8", newline="") as handle:
        subjects = [row["subject"] for row in csv.DictReader(handle)]
    assert subjects and all(not s.startswith("=") for s in subjects)


def test_markdown_escapes_untrusted_text(make_event, tmp_path):
    events = [make_event(i * 5, username="a|b<script>", ip="192.0.2.78") for i in range(5)]
    alerts = run_all_detectors(events, CONFIG)
    paths = generate_reports(ParseResult(events=events, total_rows=5), alerts, input_file="x.csv",
                             output_dir=tmp_path, config=CONFIG, analysis_time=FIXED_TIME)
    markdown = paths["markdown"].read_text(encoding="utf-8")
    assert "<script>" not in markdown and "a\\|b" in markdown


def test_malformed_rows_are_listed_in_reports(write_csv, tmp_path):
    result = parse_log_file(write_csv(
        "timestamp,username,source_ip,event_type\nbad,alice,192.0.2.1,login_failure\n"))
    paths = generate_reports(result, [], input_file="m.csv", output_dir=tmp_path,
                             config=CONFIG, analysis_time=FIXED_TIME)
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["summary"]["malformed_rows"] == 1 and data["malformed_rows"][0]["line_number"] == 2
    assert "Malformed rows" in paths["markdown"].read_text(encoding="utf-8")
