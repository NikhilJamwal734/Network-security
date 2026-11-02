"""API-010.2 regression corpus: contextual refinements and non-regressions."""
from __future__ import annotations

import pytest

from app.core.precision_review import refine_vendor_review
from app.core.vendor_review import (
    review_cisco_asa, review_fortios, review_snort, review_suricata,
)
from app.parsers.firewalls.fortios import FortiOSParser
from app.parsers.ids.snort import SnortParser
from app.parsers.ids.suricata import SuricataParser


def review(platform, lines):
    if platform == "cisco_asa":
        base = review_cisco_asa(lines)
    elif platform == "fortios":
        base = review_fortios(FortiOSParser().parse(lines))
    elif platform == "snort":
        base = review_snort(SnortParser().parse(lines))
    elif platform == "suricata":
        base = review_suricata(SuricataParser().parse(lines))
    else:
        raise AssertionError(platform)
    return refine_vendor_review(platform, lines, base)


def codes(result):
    return [x["code"] for x in result["checks"]]


def fortios(*lines):
    return review("fortios", list(lines))


def snort(*lines):
    return review("snort", list(lines))


def suricata(*lines):
    return review("suricata", list(lines))


@pytest.mark.parametrize("lines,code,line", [
    (["no logging enable"], "ASA-DEEP-003", 1),
    (["logging enable", "no logging enable"], "ASA-DEEP-003", 2),
    (["no logging enable", "logging enable", "no logging enable"], "ASA-DEEP-003", 3),
    (["ssh 0.0.0.0 0.0.0.0 outside"], "ASA-DEEP-002", 1),
    (["telnet 0.0.0.0 0.0.0.0 outside"], "ASA-DEEP-001", 1),
])
def test_asa_active_end_state(lines, code, line):
    result = review("cisco_asa", lines)
    assert codes(result) == [code]
    assert result["checks"][0]["line_number"] == line


@pytest.mark.parametrize("lines", [
    ["no logging enable", "logging enable"],
    ["telnet 0.0.0.0 0.0.0.0 outside", "no telnet 0.0.0.0 0.0.0.0 outside"],
    ["ssh 0.0.0.0 0.0.0.0 inside", "no ssh 0.0.0.0 0.0.0.0 inside"],
    ["# telnet 0.0.0.0 0.0.0.0 outside", "! no logging enable"],
    ["ssh 10.1.0.0 255.255.0.0 outside"],
])
def test_asa_suppressed_stale_and_comment_entries(lines):
    result = review("cisco_asa", lines)
    assert result["checks"] == []


def test_asa_negation_does_not_apply_to_different_interface():
    result = review("cisco_asa", ["ssh 0.0.0.0 0.0.0.0 outside", "no ssh 0.0.0.0 0.0.0.0 inside"])
    assert codes(result) == ["ASA-DEEP-002"]


def test_asa_reapplied_selector_gets_latest_line():
    result = review("cisco_asa", [
        "ssh 0.0.0.0 0.0.0.0 inside",
        "no ssh 0.0.0.0 0.0.0.0 inside",
        "ssh 0.0.0.0 0.0.0.0 inside",
    ])
    assert codes(result) == ["ASA-DEEP-002"]
    assert result["checks"][0]["line_number"] == 3


def test_fortios_disabled_policy_no_logging_flag():
    assert "FORTIOS-PREC-001" not in codes(fortios(
        "config firewall policy", "edit 5", "set status disable", "set action accept",
        "set logtraffic disable", "next", "end",
    ))


def test_fortios_explicit_policy_logging_disabled():
    result = fortios(
        "config firewall policy", "edit 5", "set action accept", "set status enable",
        "set logtraffic disable", "next", "end",
    )
    assert codes(result) == ["FORTIOS-PREC-001"]
    assert result["checks"][0]["rule_id"] == "5"


@pytest.mark.parametrize("service", ["http", "telnet", "http telnet"])
def test_fortios_explicit_wan_cleartext(service):
    result = fortios(
        "config system interface", 'edit "wan1"', "set role wan",
        f"set allowaccess {service}", "next", "end",
    )
    assert codes(result) == ["FORTIOS-PREC-002"]
    assert result["checks"][0]["severity"] == "HIGH"


def test_fortios_role_unspecified_does_not_imply_wan():
    assert fortios("config system interface", "edit wan1", "set allowaccess http", "next", "end")["checks"] == []


def test_fortios_down_interface_not_flagged():
    assert fortios("config system interface", "edit wan1", "set role wan", "set status down", "set allowaccess telnet", "next", "end")["checks"] == []


def test_fortios_repeated_policy_edits_suppress_ambiguous_old_finding():
    result = fortios(
        "config firewall policy", "edit 9", "set action accept", "set srcaddr all",
        "set dstaddr all", "set service HTTPS", "next", "edit 9",
        "set status disable", "next", "end",
    )
    assert "FORTIOS-DEEP-001" not in codes(result)
    assert result["precision"]["suppressed_preliminary_checks"] == 1


def test_fortios_repeated_service_suppressed():
    result = fortios(
        "config firewall service custom", "edit x", "set tcp-portrange 1-65535",
        "next", "edit x", "set tcp-portrange 443", "next", "end",
    )
    assert "FORTIOS-DEEP-003" not in codes(result)


def test_snort_duplicate_enabled_sid():
    result = snort(
        'alert tcp any any -> any any (sid:101; msg:"a";)',
        'alert udp any any -> any any (sid:101; msg:"b";)',
    )
    assert codes(result) == ["SNORT-PREC-001"]
    assert result["checks"][0]["line_number"] == 2


def test_snort_comment_and_distinct_sid_not_flagged():
    result = snort(
        'alert tcp any any -> any any (sid:101;)',
        '# alert tcp any any -> any any (sid:101;)',
        'alert tcp any any -> any any (sid:102;)',
    )
    assert result["checks"] == []


def test_snort_three_matching_sid_one_review_item():
    line = "alert tcp any any -> any any (sid:1001;)"
    assert codes(snort(line, line, line)) == ["SNORT-PREC-001"]


def test_suricata_duplicate_sid_same_default_gid():
    result = suricata(
        "alert udp any any -> any any (sid:201; rev:1;)",
        "alert tcp any any -> any any (sid:201; rev:2;)",
    )
    assert codes(result) == ["SURICATA-PREC-001"]
    assert result["checks"][0]["rule_id"] == "1:201"


def test_suricata_distinct_gid_not_flagged():
    result = suricata(
        "alert tcp any any -> any any (gid:1; sid:201;)",
        "alert tcp any any -> any any (gid:2; sid:201;)",
    )
    assert result["checks"] == []


def test_suricata_disabled_and_comments_not_flagged():
    result = suricata(
        "# Log some explanation", "# alert tcp any any -> any any (sid:201;)",
        "alert tcp any any -> any any (sid:201;)",
    )
    assert result["checks"] == []


def test_precision_review_metadata_and_bounding():
    report = review("cisco_asa", ["no logging enable"] * 200)
    assert len(report["checks"]) <= 40
    assert report["precision"]["suppressed_preliminary_checks"] >= 1
    assert report["precision"]["status"] == "context_refined"
    assert report["limitations"]
    assert "score" in report["interpretation"]


def test_invalid_platform_rejected():
    with pytest.raises(ValueError):
        refine_vendor_review("unknown", [], {"checks": []})


@pytest.mark.parametrize("platform,filename,payload,expected", [
    ("cisco_asa", "a.conf", b"hostname ASA\nno logging enable\nlogging enable\n", None),
    ("fortios", "f.conf", b"config system interface\n edit wan1\n set role wan\n set allowaccess telnet\n next\nend\n", "FORTIOS-PREC-002"),
    ("snort", "s.rules", b"alert tcp any any -> any any (sid:101;)\nalert udp any any -> any any (sid:101;)\n", "SNORT-PREC-001"),
    ("suricata", "u.rules", b"alert tcp any any -> any any (sid:201;)\nalert udp any any -> any any (sid:201;)\n", "SURICATA-PREC-001"),
])
def test_route_contract_and_effect(platform, filename, payload, expected):
    from fastapi.testclient import TestClient
    from app.api.main import app
    with TestClient(app) as client:
        response = client.post(f"/api/v1/analyze/precision-review?platform={platform}",
                               files={"file": (filename, payload, "text/plain")})
        previous = client.post(f"/api/v1/analyze/deep-review?platform={platform}",
                               files={"file": (filename, payload, "text/plain")})
    assert response.status_code == previous.status_code == 200, response.text
    current, old = response.json(), previous.json()
    assert current["summary"] == old["summary"]
    assert current["findings"] == old["findings"]
    assert current["assessment"] == old["assessment"]
    assert current["quality"] == old["quality"]
    assert "precision" not in old["vendor_review"]
    assert current["vendor_review"]["precision"]["status"] == "context_refined"
    if expected:
        assert expected in codes(current["vendor_review"])
    if platform == "cisco_asa":
        assert "ASA-DEEP-003" in codes(old["vendor_review"])
        assert "ASA-DEEP-003" not in codes(current["vendor_review"])


def test_suricata_full_yaml_comments_regression_route():
    from fastapi.testclient import TestClient
    from app.api.main import app
    payload = b"%YAML 1.1\n---\nrule-files:\n  - local.rules\n# Log to disk\n# drop tcp invalid rule\n"
    with TestClient(app) as client:
        response = client.post("/api/v1/analyze/precision-review?platform=suricata",
                               files={"file": ("suricata.yaml", payload, "text/plain")})
    assert response.status_code == 200
    assert response.json()["vendor_review"]["checks"] == []


def test_no_extra_field_on_older_routes():
    from fastapi.testclient import TestClient
    from app.api.main import app
    with TestClient(app) as client:
        response = client.post("/api/v1/analyze/validated?platform=snort",
                               files={"file": ("rules.rules", b"alert tcp any any -> any any (sid:2;)", "text/plain")})
    assert response.status_code == 200
    assert "vendor_review" not in response.json()
