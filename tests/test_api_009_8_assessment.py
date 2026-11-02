"""API-009.8: cross-vendor, non-executable, evidence-backed review tests.

The existing /analyze, /universal, /normalized endpoints must remain compatible.
"""

from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.core.advanced_assessment import build_advanced_assessment

PLATFORMS = ["cisco_asa", "fortios", "snort", "suricata"]
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


def normalized(platform="suricata", *, counts=None, unassessed=True):
    counts = counts or {severity: 0 for severity in SEVERITIES}
    return {
        "platform": {"platform_id": platform},
        "summary": {"severity_counts": counts},
        "coverage": {"domains": [
            {"domain": "uploaded_subset", "status": "assessed"},
            *([{"domain": "runtime_traffic", "status": "not_assessed"}] if unassessed else []),
        ]},
    }


SOURCE = {
    "cisco_asa": {
        "summary": {"total_rules": 9, "total_network_objects": 7, "total_service_objects": 2, "total_nat_rules": 1, "total_routes": 0},
        "configuration": {},
    },
    "fortios": {
        "summary": {},
        "configuration": {"firewall_policies": [{"policy_id": "123", "action": "accept"}], "address_object_names": ["LAN"], "custom_service_names": [], "interface_names": ["port1"]},
    },
    "snort": {
        "summary": {"total_rules": 2},
        "configuration": {"network_variables": ["HOME_NET"], "include_directives": 1, "output_directives": 2},
    },
    "suricata": {
        "summary": {"total_rules": 0},
        "configuration": {"home_net_visible": True, "rule_file_entries": 2, "af_packet_interfaces": 1, "eve_log_enabled": True},
    },
}


@pytest.mark.parametrize("platform", PLATFORMS)
def test_assessment_supports_each_platform(platform):
    result = build_advanced_assessment(normalized(platform), SOURCE[platform])
    assert result["platform_id"] == platform
    assert result["version"] == "1.0"
    assert result["scope"] == "uploaded_text_only"
    assert len(result["observations"]) >= 4
    assert all("source_field" in x["evidence"] for x in result["observations"])
    assert result["coverage_review"]["status"] == "partial"


@pytest.mark.parametrize("platform", PLATFORMS)
def test_every_platform_receives_a_provisional_review_score(platform):
    result = build_advanced_assessment(normalized(platform), SOURCE[platform])
    score = result["review_score"]
    assert score["value"] == 80
    assert score["status"] == "provisional"
    assert score["capped_for_incomplete_coverage"] is True
    assert score["comparable_across_platforms"] is False
    assert "NOT a validated security score" in score["interpretation"]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_platform_specific_observations_are_not_fabricated_findings(platform):
    result = build_advanced_assessment(normalized(platform), SOURCE[platform])
    assert "findings" not in result
    assert len({x["code"] for x in result["observations"]}) == len(result["observations"])
    assert all(x["status"] in ("observed", "not_visible", "not_assessed") for x in result["observations"])


@pytest.mark.parametrize("platform", PLATFORMS)
def test_never_returns_raw_config_text_or_secret_values(platform):
    source = deepcopy(SOURCE[platform])
    source["secret"] = 'set password "PLAIN_SECRET_SHOULD_NOT_ESCAPE"'
    result = build_advanced_assessment(normalized(platform), source)
    assert "PLAIN_SECRET_SHOULD_NOT_ESCAPE" not in str(result)
    assert "set password" not in str(result)


def test_score_deductions_are_deterministic():
    counts = {key: 1 for key in SEVERITIES}
    score = build_advanced_assessment(normalized(counts=counts), SOURCE["suricata"])["review_score"]
    assert score["deductions"] == {"critical": 15, "high": 7, "medium": 3, "low": 1, "info": 0, "unknown": 0}
    assert score["value"] == 74
    assert score["priority"] == "urgent_review"


def test_score_floor_zero_for_many_high_findings():
    counts = {key: 0 for key in SEVERITIES}
    counts["high"] = 1000
    result = build_advanced_assessment(normalized(counts=counts), SOURCE["suricata"])
    assert result["review_score"]["value"] == 0


def test_full_coverage_is_not_capped_but_does_not_prove_security():
    score = build_advanced_assessment(normalized(unassessed=False), SOURCE["suricata"])["review_score"]
    assert score["value"] == 100
    assert score["maximum"] == 100
    assert score["capped_for_incomplete_coverage"] is False
    assert "Zero findings never proves" in score["interpretation"]


def test_invalid_severity_count_rejected():
    counts = {key: 0 for key in SEVERITIES}
    counts["high"] = True
    with pytest.raises(ValueError):
        build_advanced_assessment(normalized(counts=counts), SOURCE["fortios"])


@pytest.mark.parametrize("bad", ["palo_alto", "", "../../../etc", None])
def test_unregistered_platform_cannot_be_assessed(bad):
    with pytest.raises(ValueError):
        build_advanced_assessment(normalized(platform=bad), {})


def test_asa_zero_routes_does_not_claim_device_has_no_routes():
    observations = build_advanced_assessment(normalized("cisco_asa"), SOURCE["cisco_asa"])["observations"]
    item = next(x for x in observations if x["code"] == "ASA-REVIEW-ROUTES")
    assert item["status"] == "not_visible"
    assert "this upload" in item["detail"]


def test_snort_include_observation_is_not_loaded_rule_coverage():
    result = build_advanced_assessment(normalized("snort"), SOURCE["snort"])
    assert result["observations"][2]["evidence"]["value"] == 1
    assert "runtime_traffic" in result["coverage_review"]["unassessed_domains"]


def test_suricata_eve_false_not_automatically_high_risk_finding():
    source = deepcopy(SOURCE["suricata"])
    source["configuration"]["eve_log_enabled"] = False
    result = build_advanced_assessment(normalized("suricata"), source)
    check = next(x for x in result["observations"] if x["code"] == "SURICATA-REVIEW-EVE")
    assert check["status"] == "not_visible"
    assert "other logging outputs" in check["detail"]


def test_missing_fortios_inventory_is_explicitly_unassessed():
    result = build_advanced_assessment(normalized("fortios"), {"configuration": {}})
    assert all(o["status"] == "not_assessed" for o in result["observations"])


def test_analyzer_does_not_mutate_adapter_reports():
    source = deepcopy(SOURCE["suricata"])
    original = deepcopy(source)
    report = normalized("suricata")
    report_original = deepcopy(report)
    build_advanced_assessment(report, source)
    assert source == original and report == report_original


def upload(text, *, platform=None, name="sample.conf", endpoint="/api/v1/analyze/assessment"):
    params = {"platform": platform} if platform else None
    with TestClient(app) as client:
        return client.post(endpoint, params=params, files={"file": (name, text.encode("utf-8"), "text/plain")})


@pytest.mark.parametrize("platform,text,filename", [
    ("cisco_asa", 'hostname ASA\nobject network TEST\n host 192.0.2.5\n', "test.conf"),
    ("fortios", 'config firewall policy\n edit 100\n set action accept\n set srcaddr "all"\n set dstaddr "all"\n set service ALL\n next\nend\n', "test.conf"),
    ("snort", 'preprocessor stream5_global: track_tcp yes\nvar HOME_NET 192.0.2.0/24\nalert tcp any any -> any 443 (msg:"test"; sid:1001;)\n', "test.conf"),
    ("suricata", 'suricata-version: "8.0"\nrule-files:\n  - local.rules\nvars:\n  address-groups:\n    HOME_NET: "[192.0.2.0/24]"\noutputs:\n  - eve-log:\n      enabled: yes\n', "test.yaml"),
])
def test_assessment_endpoint_returns_data_for_existing_non_asa_platforms(platform, text, filename):
    response = upload(text, platform=platform, name=filename)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["platform"]["platform_id"] == platform
    assert data["assessment"]["platform_id"] == platform
    assert data["assessment"]["review_score"]["status"] == "provisional"
    assert data["assessment"]["review_score"]["value"] <= 80


def test_existing_normalized_endpoint_has_no_new_assessment_field():
    text = 'rule-files:\n  - local.rules\n'
    response = upload(text, platform="suricata", name="rules.yaml", endpoint="/api/v1/analyze/normalized")
    assert response.status_code == 200
    assert "assessment" not in response.json()


def test_existing_legacy_root_unchanged():
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["version"] == "1.0.0"


def test_unsupported_extension_rejected_by_same_upload_reader():
    response = upload('rule-files:\n - local.rules\n', platform="suricata", name="file.exe")
    assert response.status_code == 400


def test_no_dangerous_file_reference_is_read(monkeypatch):
    # Extra inventory enrichment only processes structured adapter values.
    monkeypatch.setattr(Path, "open", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("opened path")))
    source = deepcopy(SOURCE["snort"])
    source["configuration"]["include_directives"] = 1
    build_advanced_assessment(normalized("snort"), source)


def test_schema_keys_match_original_normalized_report_with_one_addition():
    text = 'rule-files:\n  - local.rules\n'
    old = upload(text, platform="suricata", name="x.yaml", endpoint="/api/v1/analyze/normalized")
    new = upload(text, platform="suricata", name="x.yaml")
    assert old.status_code == new.status_code == 200
    assert set(new.json()) == set(old.json()) | {"assessment"}
    for name in old.json():
        assert new.json()[name] == old.json()[name]


def test_does_not_reparse_or_execute_uploaded_lines_in_assessment_layer():
    from app.core import advanced_assessment
    assert not hasattr(advanced_assessment, "eval")
    assert not hasattr(advanced_assessment, "exec")
