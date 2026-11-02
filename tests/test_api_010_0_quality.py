"""API-010.0 report-quality verification: four-platform accuracy guardrails.

These checks are separate from security findings and do not alter scoring.
"""

from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.core.advanced_assessment import build_advanced_assessment
from app.core.report_quality import validate_report_quality

PLATFORMS = ("cisco_asa", "fortios", "snort", "suricata")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


def reports(platform="suricata", *, with_finding=False):
    raw = {
        "code": "EXAMPLE-001", "severity": "HIGH", "title": "Demonstration finding",
        "description": "Review the setting", "recommendation": "Restrict the setting",
        "line_number": 7, "rule_id": 42,
    }
    source = {
        "summary": {"total_findings": 1 if with_finding else 0},
        "findings": [raw] if with_finding else [],
        "configuration": {},
    }
    counts = {s: (1 if s == "high" and with_finding else 0) for s in SEVERITIES}
    normalized = {
        "platform": {"platform_id": platform, "detection_method": "explicit"},
        "summary": {"total_findings": 1 if with_finding else 0, "severity_counts": counts, "security_score": None},
        "findings": [{
            "finding_id": f"{platform}:000001", "code": "EXAMPLE-001", "severity": "high",
            "title": raw["title"], "description": raw["description"],
            "recommendation": raw["recommendation"],
            "evidence": {"line_number": 7, "rule_id": 42, "related_rule_id": None},
        }] if with_finding else [],
        "coverage": {"domains": [
            {"domain": "visible_configuration", "status": "assessed"},
            {"domain": "runtime_effectiveness", "status": "not_assessed"},
        ]},
    }
    assessment = build_advanced_assessment(normalized, source)
    return normalized, source, assessment


def quality(platform="suricata", with_finding=False):
    return validate_report_quality(*reports(platform, with_finding=with_finding))


@pytest.mark.parametrize("platform", PLATFORMS)
def test_supports_all_four_platforms(platform):
    result = quality(platform)
    assert result["platform_id"] == platform
    assert result["version"] == "1.0"
    assert result["scope"] == "post_analysis_report_consistency"
    assert result["status"] == "limited_coverage"
    assert result["structural_checks_passed"] is True
    assert result["summary"]["errors"] == 0
    assert result["coverage"]["incomplete"] is True


@pytest.mark.parametrize("platform", PLATFORMS)
def test_source_finding_code_severity_and_line_are_checked(platform):
    result = quality(platform, with_finding=True)
    assert result["finding_evidence"]["findings_crosschecked_with_adapter"] == 1
    assert result["finding_evidence"]["findings_with_reported_line_references"] == 1
    assert result["finding_evidence"]["source_text_at_line_verified"] is False
    assert result["summary"]["errors"] == 0


def test_cannot_claim_perfect_security_from_zero_findings():
    q = quality("suricata")
    assert "No additional security findings" in q["interpretation"]
    assert q["coverage"]["incomplete"]


def test_does_not_modify_inputs_or_score():
    n, s, a = reports("snort", with_finding=True)
    originals = deepcopy((n, s, a))
    out = validate_report_quality(n, s, a)
    assert (n, s, a) == originals
    assert out["summary"]["errors"] == 0
    assert a["review_score"]["value"] == 80
    assert "findings" not in out


@pytest.mark.parametrize("platform", PLATFORMS)
def test_detects_wrong_total_count(platform):
    n, s, a = reports(platform)
    n["summary"]["total_findings"] = 1
    result = validate_report_quality(n, s, a)
    assert "Q-COUNT-001" in {i["code"] for i in result["issues"]}
    assert result["status"] == "review_needed"


@pytest.mark.parametrize("severity", SEVERITIES)
def test_detects_wrong_severity_totals(severity):
    n, s, a = reports()
    n["summary"]["severity_counts"][severity] = 1
    result = validate_report_quality(n, s, a)
    assert "Q-SEVERITY-001" in {x["code"] for x in result["issues"]}


def test_invalid_boolean_severity_count_is_not_accepted():
    n, s, a = reports()
    n["summary"]["severity_counts"]["high"] = True
    assert "Q-SEVERITY-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_source_severity_discrepancy_is_caught():
    n, s, a = reports(with_finding=True)
    s["findings"][0]["severity"] = "LOW"
    assert "Q-SOURCE-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_source_line_reference_discrepancy_is_caught():
    n, s, a = reports(with_finding=True)
    s["findings"][0]["line_number"] = 99
    assert "Q-SOURCE-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_unverifiable_line_reference_is_not_claimed_to_be_verified():
    n, s, a = reports(with_finding=True)
    result = validate_report_quality(n, s, a)
    assert result["finding_evidence"]["source_text_at_line_verified"] is False


def test_invalid_normalized_line_number_flagged():
    n, s, a = reports(with_finding=True)
    n["findings"][0]["evidence"]["line_number"] = 0
    assert "Q-EVIDENCE-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_duplicate_ids_flagged():
    n, s, a = reports(with_finding=True)
    n["findings"].append(deepcopy(n["findings"][0]))
    s["findings"].append(deepcopy(s["findings"][0]))
    n["summary"]["total_findings"] = 2
    s["summary"]["total_findings"] = 2
    n["summary"]["severity_counts"]["high"] = 2
    assert "Q-FINDING-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_score_tampering_is_caught():
    n, s, a = reports()
    a["review_score"]["value"] = 100
    assert "Q-SCORE-003" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_score_cannot_be_labeled_comparable():
    n, s, a = reports()
    a["review_score"]["comparable_across_platforms"] = True
    assert "Q-SCORE-002" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_duplicate_coverage_domain_flagged():
    n, s, a = reports()
    n["coverage"]["domains"].append({"domain": "runtime_effectiveness", "status": "not_assessed"})
    assert "Q-COVERAGE-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_suricata_rule_ref_should_not_be_implicitly_assessed():
    n, s, a = reports("suricata")
    s["configuration"]["rule_file_entries"] = 2
    assert "Q-SURICATA-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_snort_include_paths_should_not_be_implicitly_assessed():
    n, s, a = reports("snort")
    s["configuration"]["include_directives"] = 2
    assert "Q-SNORT-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_snort_parsed_rule_count_inconsistency_flagged():
    n, s, a = reports("snort")
    s["summary"].update(total_rules=2, active_rules=2, disabled_rules=0)
    s["configuration"]["ids_rules"] = [{"enabled": True}]
    result = validate_report_quality(n, s, a)
    assert "Q-IDS-001" in {x["code"] for x in result["issues"]}
    assert "Q-IDS-002" in {x["code"] for x in result["issues"]}


def test_fortios_inconsistent_policy_count_flagged():
    n, s, a = reports("fortios")
    s["summary"]["firewall_policies"] = 2
    s["configuration"]["firewall_policies"] = [{"policy_id": "1"}]
    assert "Q-FORTIOS-001" in {x["code"] for x in validate_report_quality(n, s, a)["issues"]}


def test_inventory_observation_mismatch_flagged():
    n, s, a = reports("fortios")
    s["configuration"]["firewall_policies"] = [{"policy_id": "1"}]
    a = build_advanced_assessment(n, s)
    s["configuration"]["firewall_policies"].append({"policy_id": "2"})
    result = validate_report_quality(n, s, a)
    assert "Q-INVENTORY-001" in {x["code"] for x in result["issues"]}


def test_referenced_config_paths_and_secrets_are_not_leaked():
    n, s, a = reports("suricata")
    s["secret"] = 'set password VERY_SECRET_TOKEN'
    s["configuration"]["rule_file_entries"] = 0
    result = validate_report_quality(n, s, a)
    assert "VERY_SECRET_TOKEN" not in str(result)
    assert "set password" not in str(result)


@pytest.mark.parametrize("platform", ["palo_alto", "", "../../etc", None])
def test_unsupported_platform_refused(platform):
    n, s, a = reports()
    n["platform"]["platform_id"] = platform
    with pytest.raises(ValueError):
        validate_report_quality(n, s, a)


@pytest.mark.parametrize("platform,filename,text", [
    ("cisco_asa", "asa.conf", 'hostname FW\nobject network LAN\n host 192.0.2.2\n'),
    ("fortios", "fw.conf", 'config firewall policy\n edit 1\n set action accept\n set srcaddr "all"\n set dstaddr "all"\n set service ALL\n next\nend\n'),
    ("snort", "snort.conf", 'preprocessor stream5_global: track_tcp yes\nvar HOME_NET 192.0.2.0/24\nalert tcp any any -> any 443 (msg:"Demo"; sid:1001;)\n'),
    ("suricata", "suri.yaml", 'suricata-version: "8.0"\nrule-files:\n - local.rules\nvars:\n  address-groups:\n    HOME_NET: "[192.0.2.0/24]"\n'),
])
def test_validated_endpoint_all_platforms(platform, filename, text):
    with TestClient(app) as client:
        result = client.post('/api/v1/analyze/validated', params={'platform': platform},
            files={'file': (filename, text.encode(), 'text/plain')})
    assert result.status_code == 200, result.text
    data = result.json()
    assert data['platform']['platform_id'] == platform
    assert data['quality']['platform_id'] == platform
    assert data['quality']['summary']['errors'] == 0
    assert 'assessment' in data
    assert data['summary']['total_findings'] == len(data['findings'])
    assert data['quality']['coverage']['incomplete'] is True


def test_normalized_and_assessment_contracts_unchanged():
    text = 'rule-files:\n - local.rules\n'
    with TestClient(app) as client:
        f = {'file': ('suri.yaml', text.encode(), 'text/plain')}
        norm = client.post('/api/v1/analyze/normalized', params={'platform': 'suricata'}, files=f)
        ass = client.post('/api/v1/analyze/assessment', params={'platform': 'suricata'}, files=f)
        val = client.post('/api/v1/analyze/validated', params={'platform': 'suricata'}, files=f)
    assert norm.status_code == ass.status_code == val.status_code == 200
    assert 'quality' not in norm.json() and 'assessment' not in norm.json()
    assert 'quality' not in ass.json()
    assert set(val.json()) == set(ass.json()) | {'quality'}
    for key in ass.json():
        assert ass.json()[key] == val.json()[key]


def test_bad_extension_uses_existing_upload_validation():
    with TestClient(app) as client:
        result = client.post('/api/v1/analyze/validated', files={'file': ('config.exe', b'rule-files:\n - a.rules\n')})
    assert result.status_code == 400


def test_legacy_root_response_preserved():
    with TestClient(app) as client:
        assert client.get('/').json()['version'] == '1.0.0'
        assert '/api/v1/analyze/assessment' in app.openapi()['paths']
        assert '/api/v1/analyze/validated' in app.openapi()['paths']


def test_never_open_referenced_paths(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Referenced file path was opened')
    monkeypatch.setattr(Path, 'open', forbidden)
    q = quality('suricata')
    assert q['platform_id'] == 'suricata'
