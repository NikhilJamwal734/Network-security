from pathlib import Path

from app.analyzer.engine import analyze_firewall
from app.parsers.firewalls.cisco_asa import CiscoASAParser


CONFIG_PATH = Path("configs/firewall.conf")


def load_real_firewall():
    config_text = CONFIG_PATH.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    parser = CiscoASAParser()

    return parser.parse(config_text.splitlines())


def test_real_firewall_config_parses_and_analyzes():
    assert CONFIG_PATH.exists()

    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    assert firewall.vendor == "Cisco ASA"
    assert firewall.hostname == "ASA-FIREWALL"

    assert len(firewall.networks) == 7
    assert len(firewall.services) == 2
    assert len(firewall.rules) == 9
    assert len(firewall.nat_rules) == 1

    codes = [finding.code for finding in findings]

    assert "FW-001" in codes
    assert "FW-002" in codes
    assert "FW-003" in codes
    assert "FW-004" in codes
    assert "FW-006" in codes
    assert "FW-007" in codes
    assert "FW-008" in codes
    assert "FW-010" in codes


def test_real_firewall_config_has_expected_finding_counts():
    firewall = load_real_firewall()
    findings = analyze_firewall(firewall)

    counts = {}

    for finding in findings:
        counts[finding.code] = counts.get(finding.code, 0) + 1

    assert counts["FW-001"] == 1
    assert counts["FW-002"] == 2
    assert counts["FW-003"] == 9
    assert counts["FW-004"] == 2
    assert counts["FW-006"] == 2
    assert counts["FW-007"] == 1
    assert counts["FW-008"] == 1
    assert counts["FW-010"] == 1
    assert counts["FW-012"] == 5
    assert counts["FW-013"] == 2
    assert counts["FW-014"] == 2
    assert counts["FW-016"] == 1

    assert len(findings) == 29

    