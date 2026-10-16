import json

from src.main import EXIT_INVALID_INPUT, EXIT_OK, EXIT_PROCESSING_ERROR, main
from conftest import HEADER


def test_analyze_sample_succeeds_and_writes_reports(sample_log, tmp_path, capsys):
    code = main(["analyze", "--input", str(sample_log), "--output", str(tmp_path)])
    out = capsys.readouterr()
    assert code == EXIT_OK
    assert "Alerts generated" in out.out
    assert "malformed row(s) skipped" in out.err  # warned, but not fatal
    for name in ("soc_report.json", "soc_alerts.csv", "soc_summary.md"):
        assert (tmp_path / name).is_file()


def test_sample_triggers_every_rule_and_severity(sample_log, tmp_path):
    main(["analyze", "--input", str(sample_log), "--output", str(tmp_path)])
    data = json.loads((tmp_path / "soc_report.json").read_text(encoding="utf-8"))
    assert set(data["summary"]["alerts_by_rule"]) == {
        "failed_logins_by_ip", "failed_logins_by_user", "success_after_failures",
        "off_hours_activity", "multiple_accounts_from_ip",
    }
    assert all(count > 0 for count in data["summary"]["alerts_by_severity"].values())
    assert data["summary"]["malformed_rows"] == 6


def test_threshold_option_changes_results(sample_log, tmp_path):
    main(["analyze", "--input", str(sample_log), "--output", str(tmp_path / "a")])
    main(["analyze", "--input", str(sample_log), "--output", str(tmp_path / "b"), "--threshold", "20"])
    default = json.loads((tmp_path / "a" / "soc_report.json").read_text(encoding="utf-8"))
    strict = json.loads((tmp_path / "b" / "soc_report.json").read_text(encoding="utf-8"))
    assert "failed_logins_by_ip" in default["summary"]["alerts_by_rule"]
    assert "failed_logins_by_ip" not in strict["summary"]["alerts_by_rule"]


def test_validate_exit_codes(sample_log, write_csv):
    assert main(["validate", "--input", str(sample_log)]) == EXIT_INVALID_INPUT  # has malformed rows
    clean = write_csv(HEADER + "2026-03-02T09:00:00Z,alice,192.0.2.10,login_success\n")
    assert main(["validate", "--input", str(clean)]) == EXIT_OK


def test_invalid_input_exit_codes(write_csv, tmp_path, capsys):
    assert main(["analyze", "--input", str(tmp_path / "nope.csv")]) == EXIT_INVALID_INPUT
    assert main(["analyze", "--input", str(write_csv(""))]) == EXIT_INVALID_INPUT
    assert main(["analyze", "--input", str(write_csv("a,b\n1,2\n"))]) == EXIT_INVALID_INPUT
    assert "Missing required column" in capsys.readouterr().err


def test_bad_threshold_and_bad_config_are_invalid_input(write_csv, tmp_path):
    clean = write_csv(HEADER + "2026-03-02T09:00:00Z,alice,192.0.2.10,login_success\n")
    assert main(["analyze", "--input", str(clean), "--output", str(tmp_path), "--threshold", "0"]) == EXIT_INVALID_INPUT
    assert main(["analyze", "--input", str(clean), "--output", str(tmp_path), "--config", str(tmp_path / "x.json")]) == EXIT_INVALID_INPUT


def test_unwritable_output_is_a_processing_error(write_csv, tmp_path):
    clean = write_csv(HEADER + "2026-03-02T09:00:00Z,alice,192.0.2.10,login_success\n")
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    assert main(["analyze", "--input", str(clean), "--output", str(blocker)]) == EXIT_PROCESSING_ERROR


def test_analysis_does_not_modify_the_input(sample_log, tmp_path):
    before = sample_log.read_bytes()
    main(["analyze", "--input", str(sample_log), "--output", str(tmp_path)])
    assert sample_log.read_bytes() == before
