import json
import subprocess
import sys
from pathlib import Path


CONFIG_PATH = Path("configs/firewall.conf")
REPORT_PATH = Path("reports/firewall_report.json")


def run_cli(config_path):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "app.main",
            str(config_path),
        ],
        capture_output=True,
        text=True,
    )


def test_cli_analyzes_real_configuration_successfully():
    result = run_cli(CONFIG_PATH)

    assert result.returncode == 0

    assert "FIREWALL CONFIGURATION ANALYZER" in result.stdout
    assert "SECURITY FINDINGS" in result.stdout
    assert "SECURITY REPORT SUMMARY" in result.stdout
    assert "ANALYSIS COMPLETE" in result.stdout


def test_cli_reports_expected_configuration_counts():
    result = run_cli(CONFIG_PATH)

    assert result.returncode == 0

    assert "Vendor       : Cisco ASA" in result.stdout
    assert "Hostname     : ASA-FIREWALL" in result.stdout
    assert "Networks     : 7" in result.stdout
    assert "Services     : 2" in result.stdout
    assert "Rules        : 9" in result.stdout
    assert "NAT rules    : 1" in result.stdout
    assert "Routes       : 0" in result.stdout


def test_cli_reports_expected_findings():
    result = run_cli(CONFIG_PATH)

    assert result.returncode == 0

    assert "[CRITICAL] FW-001" in result.stdout
    assert "[HIGH] FW-002" in result.stdout
    assert "[LOW] FW-003" in result.stdout
    assert "[MEDIUM] FW-004" in result.stdout
    assert "[LOW] FW-006" in result.stdout
    assert "[HIGH] FW-007" in result.stdout
    assert "[MEDIUM] FW-008" in result.stdout
    assert "[HIGH] FW-010" in result.stdout


def test_cli_reports_expected_security_summary():
    result = run_cli(CONFIG_PATH)

    assert result.returncode == 0

    assert "Security Score     : 21/100" in result.stdout
    assert "Critical Findings  : 1" in result.stdout
    assert "High Findings      : 4" in result.stdout
    assert "Medium Findings    : 3" in result.stdout
    assert "Low Findings       : 21" in result.stdout
    assert "Total Findings     : 29" in result.stdout


def test_cli_creates_json_report():
    if REPORT_PATH.exists():
        REPORT_PATH.unlink()

    result = run_cli(CONFIG_PATH)

    assert result.returncode == 0
    assert REPORT_PATH.exists()


def test_cli_json_report_contains_expected_data():
    result = run_cli(CONFIG_PATH)

    assert result.returncode == 0
    assert REPORT_PATH.exists()

    report_data = json.loads(
        REPORT_PATH.read_text(
            encoding="utf-8"
        )
    )

    assert report_data["vendor"] == "Cisco ASA"
    assert report_data["hostname"] == "ASA-FIREWALL"

    summary = report_data["summary"]

    assert summary["total_rules"] == 9
    assert summary["total_network_objects"] == 7
    assert summary["total_service_objects"] == 2
    assert summary["total_nat_rules"] == 1
    assert summary["total_routes"] == 0

    assert summary["total_findings"] == 29
    assert summary["critical_findings"] == 1
    assert summary["high_findings"] == 4
    assert summary["medium_findings"] == 3
    assert summary["low_findings"] == 21

    assert summary["security_score"] == 21
    assert summary["risk_level"] == "CRITICAL"


def test_cli_json_report_contains_source_information():
    result = run_cli(CONFIG_PATH)

    assert result.returncode == 0

    report_data = json.loads(
        REPORT_PATH.read_text(
            encoding="utf-8"
        )
    )

    assert "source" in report_data
    assert (
        report_data["source"]["configuration_file"]
        == str(CONFIG_PATH)
    )


def test_cli_json_report_contains_all_findings():
    result = run_cli(CONFIG_PATH)

    assert result.returncode == 0

    report_data = json.loads(
        REPORT_PATH.read_text(
            encoding="utf-8"
        )
    )

    findings = report_data["findings"]

    assert len(findings) == 29

    codes = [
        finding["code"]
        for finding in findings
    ]

    assert codes.count("FW-001") == 1
    assert codes.count("FW-002") == 2
    assert codes.count("FW-003") == 9
    assert codes.count("FW-004") == 2
    assert codes.count("FW-006") == 2
    assert codes.count("FW-007") == 1
    assert codes.count("FW-008") == 1
    assert codes.count("FW-010") == 1


def test_cli_missing_file_fails_cleanly(tmp_path):
    missing_config = tmp_path / "does_not_exist.conf"

    result = run_cli(missing_config)

    assert result.returncode != 0
    assert "ERROR: File not found:" in result.stdout


def test_cli_directory_path_fails_cleanly(tmp_path):
    result = run_cli(tmp_path)

    assert result.returncode != 0
    assert "ERROR: Path is not a file:" in result.stdout


def test_cli_without_arguments_shows_usage():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.main",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0

    assert (
        "Usage: python -m app.main <config-file>"
        in result.stdout
    )