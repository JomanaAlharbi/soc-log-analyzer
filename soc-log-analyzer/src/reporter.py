"""Build and write JSON, CSV and Markdown reports from detection results."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .config import DetectionConfig
from .detectors import RECOMMENDED_ACTIONS, RULE_NAMES, Alert, Severity
from .log_parser import ParseResult

JSON_FILENAME = "soc_report.json"
CSV_FILENAME = "soc_alerts.csv"
MARKDOWN_FILENAME = "soc_summary.md"

DISCLAIMER = (
    "Alerts are indicators that deserve human review. They do not prove that an "
    "attack happened or that any account was compromised, and an absence of alerts "
    "does not prove an absence of malicious activity."
)
MAX_EVENTS_SHOWN_IN_MARKDOWN = 10
MAX_ROW_ERRORS_SHOWN_IN_MARKDOWN = 20


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def build_report(
    parse_result: ParseResult,
    alerts: Sequence[Alert],
    *,
    input_file: str | Path,
    config: DetectionConfig,
    analysis_time: datetime | None = None,
) -> dict[str, Any]:
    """Assemble the full report as a plain dictionary (the single source for
    all three output formats)."""
    analysis_time = analysis_time or utc_now()
    by_severity = {s.name: 0 for s in sorted(Severity, reverse=True)}
    by_rule: dict[str, int] = {}
    for alert in alerts:
        by_severity[alert.severity.name] += 1
        by_rule[alert.rule_id] = by_rule.get(alert.rule_id, 0) + 1

    events = parse_result.events
    return {
        "report_metadata": {
            "tool": "soc-log-analyzer",
            "tool_version": __version__,
            "analysis_timestamp": analysis_time.isoformat(),
            "input_file": Path(input_file).name,
            "disclaimer": DISCLAIMER,
        },
        "summary": {
            "total_rows_read": parse_result.total_rows,
            "total_events": len(events),
            "malformed_rows": len(parse_result.errors),
            "failed_logins": sum(1 for e in events if e.is_failure),
            "successful_logins": sum(1 for e in events if e.is_success),
            "total_alerts": len(alerts),
            "alerts_by_severity": by_severity,
            "alerts_by_rule": by_rule,
        },
        "configuration": asdict(config),
        "alerts": [a.to_dict() for a in alerts],
        "malformed_rows": [
            {"line_number": e.line_number, "message": e.message}
            for e in parse_result.errors
        ],
    }


# ---------------------------------------------------------------- JSON
def write_json_report(report: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


# ----------------------------------------------------------------- CSV
CSV_COLUMNS = (
    "alert_id",
    "severity",
    "rule_id",
    "rule_name",
    "subject",
    "first_seen",
    "last_seen",
    "event_count",
    "explanation",
    "recommended_actions",
    "analysis_timestamp",
    "input_file",
)


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection: log-derived text such as a
    username beginning with '=' must not be executed when opened in Excel."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def write_csv_report(report: dict[str, Any], path: Path) -> None:
    meta = report["report_metadata"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for alert in report["alerts"]:
            row = [
                alert["alert_id"],
                alert["severity"],
                alert["rule_id"],
                alert["rule_name"],
                alert["subject"],
                alert["first_seen"],
                alert["last_seen"],
                alert["event_count"],
                alert["explanation"],
                " | ".join(alert["recommended_actions"]),
                meta["analysis_timestamp"],
                meta["input_file"],
            ]
            writer.writerow([_csv_safe(cell) for cell in row])


# ------------------------------------------------------------ Markdown
def _md(value: Any) -> str:
    """Make untrusted text safe for a Markdown table cell or line."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def render_markdown(report: dict[str, Any]) -> str:
    meta, summary = report["report_metadata"], report["summary"]
    lines: list[str] = [
        "# SOC Log Analyzer - Analysis Summary",
        "",
        f"- **Input file:** `{_md(meta['input_file'])}`",
        f"- **Analysis timestamp (UTC):** {meta['analysis_timestamp']}",
        f"- **Tool version:** {meta['tool_version']}",
        "",
        f"> {meta['disclaimer']}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total events analysed | {summary['total_events']} |",
        f"| Failed logins | {summary['failed_logins']} |",
        f"| Successful logins | {summary['successful_logins']} |",
        f"| Malformed rows skipped | {summary['malformed_rows']} |",
        f"| Total alerts | {summary['total_alerts']} |",
        "",
        "## Alerts by severity",
        "",
        "| Severity | Alerts |",
        "|---|---|",
    ]
    for severity, count in summary["alerts_by_severity"].items():
        lines.append(f"| {severity} | {count} |")

    lines += ["", "## Alerts", ""]
    if not report["alerts"]:
        lines += ["No alerts were generated for this input.", ""]
    for alert in report["alerts"]:
        lines += [
            f"### {alert['alert_id']} - {alert['severity']} - {_md(alert['rule_name'])}",
            "",
            f"- **Subject:** `{_md(alert['subject'])}`",
            f"- **First seen:** {alert['first_seen']}",
            f"- **Last seen:** {alert['last_seen']}",
            f"- **Events:** {alert['event_count']}",
            f"- **Why this alert was generated:** {_md(alert['explanation'])}",
            "",
            "**Supporting events**" + (
                f" (first {MAX_EVENTS_SHOWN_IN_MARKDOWN} of {alert['event_count']})"
                if alert["event_count"] > MAX_EVENTS_SHOWN_IN_MARKDOWN
                else ""
            ),
            "",
            "| Line | Timestamp (UTC) | Username | Source IP | IP type | Event |",
            "|---|---|---|---|---|---|",
        ]
        for event in alert["events"][:MAX_EVENTS_SHOWN_IN_MARKDOWN]:
            lines.append(
                f"| {event['line_number']} | {event['timestamp']} | "
                f"{_md(event['username'])} | {event['source_ip']} | "
                f"{event['ip_category']} | {event['event_type']} |"
            )
        lines.append("")

    lines += ["## Recommended defensive actions by alert type", ""]
    present = sorted({a["rule_id"] for a in report["alerts"]})
    if not present:
        lines += ["_No alert types to report._", ""]
    for rule_id in present:
        lines.append(f"**{RULE_NAMES[rule_id]}**")
        lines.append("")
        lines += [f"- {action}" for action in RECOMMENDED_ACTIONS[rule_id]]
        lines.append("")

    if report["malformed_rows"]:
        lines += ["## Malformed rows (skipped)", ""]
        shown = report["malformed_rows"][:MAX_ROW_ERRORS_SHOWN_IN_MARKDOWN]
        lines += [f"- {_md(row['message'])}" for row in shown]
        hidden = len(report["malformed_rows"]) - len(shown)
        if hidden > 0:
            lines.append(f"- ... and {hidden} more (see the JSON report)")
        lines.append("")
    return "\n".join(lines)


def write_markdown_report(report: dict[str, Any], path: Path) -> None:
    path.write_text(render_markdown(report), encoding="utf-8")


# ----------------------------------------------------------- Orchestration
def generate_reports(
    parse_result: ParseResult,
    alerts: Sequence[Alert],
    *,
    input_file: str | Path,
    output_dir: str | Path,
    config: DetectionConfig,
    analysis_time: datetime | None = None,
) -> dict[str, Path]:
    """Write all three reports and return their paths."""
    report = build_report(
        parse_result,
        alerts,
        input_file=input_file,
        config=config,
        analysis_time=analysis_time,
    )
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out_dir / JSON_FILENAME,
        "csv": out_dir / CSV_FILENAME,
        "markdown": out_dir / MARKDOWN_FILENAME,
    }
    write_json_report(report, paths["json"])
    write_csv_report(report, paths["csv"])
    write_markdown_report(report, paths["markdown"])
    return paths
