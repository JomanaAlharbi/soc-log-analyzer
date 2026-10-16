"""Command-line interface.

    python -m src.main analyze  --input logs/sample_auth.csv --output reports
    python -m src.main validate --input logs/sample_auth.csv

Exit codes:
    0  success
    2  invalid input (missing file, bad columns, empty file, bad configuration or
       arguments; for `validate`, also when malformed rows are found)
    3  processing error (for example the output directory cannot be written)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import ConfigError, load_config, with_threshold
from .detectors import run_all_detectors
from .log_parser import LogFormatError, ParseResult, parse_log_file
from .reporter import build_report, generate_reports

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_PROCESSING_ERROR = 3

MAX_ROW_ERRORS_PRINTED = 10


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="SOC Log Analyzer: detect suspicious authentication activity "
        "in CSV logs. Read-only; no network access.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="analyze a log and write reports")
    analyze.add_argument("--input", "-i", required=True, help="path to the CSV log file")
    analyze.add_argument("--output", "-o", default="reports", help="report directory (default: reports)")
    analyze.add_argument("--config", "-c", help="path to a detection rules JSON file")
    analyze.add_argument(
        "--threshold",
        "-t",
        type=int,
        help="override the failed-login threshold for rules 1 and 2",
    )
    analyze.set_defaults(handler=_cmd_analyze)

    validate = subparsers.add_parser("validate", help="check a log file without analysing it")
    validate.add_argument("--input", "-i", required=True, help="path to the CSV log file")
    validate.set_defaults(handler=_cmd_validate)
    return parser


def _print_row_errors(result: ParseResult, stream) -> None:
    for error in result.errors[:MAX_ROW_ERRORS_PRINTED]:
        print(f"  - {error.message}", file=stream)
    hidden = len(result.errors) - MAX_ROW_ERRORS_PRINTED
    if hidden > 0:
        print(f"  ... and {hidden} more", file=stream)


def _cmd_validate(args: argparse.Namespace) -> int:
    result = parse_log_file(args.input)
    print(f"Rows read: {result.total_rows} (valid: {len(result.events)}, malformed: {len(result.errors)})")
    if result.errors:
        print("Validation found malformed rows:", file=sys.stderr)
        _print_row_errors(result, sys.stderr)
        return EXIT_INVALID_INPUT
    print("Validation passed: all rows are valid.")
    return EXIT_OK


def _cmd_analyze(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.threshold is not None:
        config = with_threshold(config, args.threshold)

    result = parse_log_file(args.input)
    if result.errors:
        print(
            f"Warning: {len(result.errors)} malformed row(s) skipped:", file=sys.stderr
        )
        _print_row_errors(result, sys.stderr)

    alerts = run_all_detectors(result.events, config)
    paths = generate_reports(
        result, alerts, input_file=args.input, output_dir=args.output, config=config
    )
    summary = build_report(result, alerts, input_file=args.input, config=config)["summary"]

    severities = ", ".join(f"{k}: {v}" for k, v in summary["alerts_by_severity"].items())
    print(f"SOC Log Analyzer {__version__}")
    print(f"Input file       : {Path(args.input).name}")
    print(f"Events analysed  : {summary['total_events']} "
          f"(failed: {summary['failed_logins']}, successful: {summary['successful_logins']}, "
          f"malformed rows skipped: {summary['malformed_rows']})")
    print(f"Alerts generated : {summary['total_alerts']} ({severities})")
    print("Reports written  :")
    for label in ("json", "csv", "markdown"):
        print(f"  - {paths[label]}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)  # argparse itself exits with code 2 on usage errors
    try:
        return args.handler(args)
    except (LogFormatError, ConfigError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except OSError as exc:
        print(f"Processing error: {exc}", file=sys.stderr)
        return EXIT_PROCESSING_ERROR
    except Exception as exc:  # noqa: BLE001 - last-resort guard for a CLI tool
        print(f"Unexpected processing error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_PROCESSING_ERROR


if __name__ == "__main__":
    sys.exit(main())
