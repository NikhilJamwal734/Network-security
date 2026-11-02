import json
from pathlib import Path

from app.analyzer.engine import analyze_firewall
from app.parsers.firewalls.cisco_asa import CiscoASAParser
from app.reporting.report import (
    ReportGenerator,
    ReportSummary,
    SecurityReport,
    generate_report,
)


CONFIG_PATH = Path("configs/firewall.conf")


def load_real_firewall():
    config_text = CONFIG_PATH.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    parser = CiscoASAParser()

    return parser.parse(
        config_text.splitlines()
    )


def test_report_generator_returns_security_report():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    generator = ReportGenerator()

    report = generator.generate(
        firewall,
        findings,
    )

    assert isinstance(
        report,
        SecurityReport,
    )

    assert report.vendor == "Cisco ASA"
    assert report.hostname == "ASA-FIREWALL"


def test_report_summary_contains_correct_configuration_counts():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    summary = report.summary

    assert isinstance(
        summary,
        ReportSummary,
    )

    assert summary.total_rules == 9
    assert summary.total_network_objects == 7
    assert summary.total_service_objects == 2
    assert summary.total_nat_rules == 1
    assert summary.total_routes == 0
    assert summary.security_score == 21


def test_report_summary_contains_correct_finding_counts():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    summary = report.summary

    assert summary.total_findings == 29

    assert summary.critical_findings == 1
    assert summary.high_findings == 4
    assert summary.medium_findings == 3
    assert summary.low_findings == 21


def test_report_security_score_matches_scoring_model():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    assert report.summary.security_score == 21


def test_report_risk_level_is_critical_when_critical_finding_exists():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    assert report.summary.risk_level == "CRITICAL"


def test_report_contains_all_findings():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    assert len(report.findings) == len(findings)

    report_codes = [
        finding["code"]
        for finding in report.findings
    ]

    finding_codes = [
        finding.code
        for finding in findings
    ]

    assert sorted(report_codes) == sorted(
        finding_codes
    )


def test_report_findings_are_sorted_by_severity():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    severities = [
        finding["severity"]
        for finding in report.findings
    ]

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    numeric_order = [
        severity_order.get(
            severity.strip().upper(),
            99,
        )
        for severity in severities
    ]

    assert numeric_order == sorted(
        numeric_order
    )


def test_report_findings_have_expected_fields():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    expected_fields = {
        "severity",
        "code",
        "rule_id",
        "line_number",
        "title",
        "description",
        "recommendation",
        "related_rule_id",
    }

    assert report.findings

    for finding in report.findings:
        assert set(finding.keys()) == expected_fields


def test_report_to_dict_has_expected_top_level_structure():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    data = report.to_dict()

    assert set(data.keys()) == {
        "vendor",
        "hostname",
        "summary",
        "findings",
        "warnings",
    }

    assert data["vendor"] == "Cisco ASA"
    assert data["hostname"] == "ASA-FIREWALL"

    assert isinstance(
        data["summary"],
        dict,
    )

    assert isinstance(
        data["findings"],
        list,
    )

    assert isinstance(
        data["warnings"],
        list,
    )


def test_report_to_dict_is_json_serializable():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report = ReportGenerator().generate(
        firewall,
        findings,
    )

    data = report.to_dict()

    serialized = json.dumps(
        data,
        indent=4,
    )

    assert isinstance(
        serialized,
        str,
    )

    assert '"vendor": "Cisco ASA"' in serialized
    assert '"hostname": "ASA-FIREWALL"' in serialized


def test_convenience_generate_report_matches_generator():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    report_from_class = ReportGenerator().generate(
        firewall,
        findings,
    )

    report_from_function = generate_report(
        firewall,
        findings,
    )

    assert report_from_function.vendor == (
        report_from_class.vendor
    )

    assert report_from_function.hostname == (
        report_from_class.hostname
    )

    assert report_from_function.summary == (
        report_from_class.summary
    )

    assert report_from_function.findings == (
        report_from_class.findings
    )

    assert report_from_function.warnings == (
        report_from_class.warnings
    )