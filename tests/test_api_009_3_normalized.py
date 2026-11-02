"""API-009.3: opt-in normalized security models and endpoint tests."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.core.catalog import create_default_registry
from app.core.normalization import normalize_cisco_asa_report
from app.core.normalized_models import (
    AnalysisCoverage,
    CoverageDomain,
    CoverageStatus,
    FindingEvidence,
    NormalizedFinding,
    NormalizedReport,
    NormalizedSummary,
    PlatformIdentity,
    Severity,
)
from app.core.platforms import DeviceFamily

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "configs" / "firewall.conf"
REGISTRY = create_default_registry()
DESCRIPTOR = REGISTRY.get("cisco_asa").descriptor
ASA = (
    "hostname NORMALIZED-ASA\n"
    "object network TEST-SERVER\n"
    " host 192.0.2.5\n"
    "access-list OUTSIDE extended permit tcp any any eq 443\n"
)


def post(path, content=ASA, filename="example.conf", params=None):
    if isinstance(content, str):
        content = content.encode("utf-8")
    with TestClient(app) as client:
        return client.post(
            path,
            params=params,
            files={"file": (filename, content, "text/plain")},
        )


def normalize_sample():
    result = REGISTRY.get("cisco_asa").analyze(ASA.splitlines())
    return normalize_cisco_asa_report(result, DESCRIPTOR)


def test_normalized_endpoint_is_registered():
    assert "/api/v1/analyze/normalized" in app.openapi()["paths"]


def test_normalized_endpoint_reports_verified_platform():
    response = post("/api/v1/analyze/normalized")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["schema_version"] == "1.0"
    assert data["platform"] == {
        "platform_id": "cisco_asa",
        "display_name": "Cisco ASA",
        "family": "firewall",
        "hostname": "NORMALIZED-ASA",
        "detection_method": "automatic",
    }
    assert data["coverage"]["assessment_type"] == "static_configuration"
    assert isinstance(data["findings"], list)
    assert data["summary"]["total_findings"] == len(data["findings"])


def test_normalized_endpoint_explicit_selection():
    response = post(
        "/api/v1/analyze/normalized",
        "hostname SIMPLE-ASA\n",
        params={"platform": "cisco_asa"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["platform"]["detection_method"] == "explicit"


def test_normalized_schema_json_round_trip():
    serialized = normalize_sample().to_dict()
    assert json.loads(json.dumps(serialized)) == serialized


def test_normalized_model_does_not_mutate_legacy_report():
    report = REGISTRY.get("cisco_asa").analyze(ASA.splitlines())
    original = deepcopy(report)
    normalize_cisco_asa_report(report, DESCRIPTOR)
    assert report == original


def test_normalized_sample_matches_known_score_and_severities():
    assert SAMPLE.exists(), "Sample config required: configs/firewall.conf"
    report = REGISTRY.get("cisco_asa").analyze(
        SAMPLE.read_text(encoding="utf-8-sig").splitlines()
    )
    normalized = normalize_cisco_asa_report(report, DESCRIPTOR).to_dict()
    assert normalized["summary"]["security_score"] == 21
    assert normalized["summary"]["total_findings"] == 29
    assert normalized["summary"]["severity_counts"] == {
        "critical": 1,
        "high": 4,
        "medium": 3,
        "low": 21,
        "info": 0,
        "unknown": 0,
    }
    assert len({f["finding_id"] for f in normalized["findings"]}) == 29


def test_new_endpoint_matches_legacy_without_changing_legacy_shape():
    original = post("/api/v1/analyze")
    universal = post("/api/v1/analyze/universal")
    normalized = post("/api/v1/analyze/normalized")
    assert original.status_code == universal.status_code == normalized.status_code == 200
    universal_data = universal.json()
    universal_data.pop("platform_detection")
    assert universal_data == original.json()
    assert "schema_version" not in original.json()
    assert "schema_version" in normalized.json()


@pytest.mark.parametrize(
    "content,filename,code",
    [
        (b"", "input.conf", 400),
        (b"\xff\xff", "input.conf", 400),
        (ASA, "input.exe", 400),
        (b"A" * (2 * 1024 * 1024 + 1), "input.conf", 413),
        ("something completely unrelated\n", "input.conf", 422),
        ('alert tcp any any -> $HOME_NET any (msg:"x"; sid:1;)', "input.conf", 422),
    ],
    ids=[
        "empty-upload-400",
        "invalid-utf8-400",
        "unsupported-extension-400",
        "oversize-input-conf-413",
        "unknown-format-422",
        "snort-unsupported-422",
    ],
)
def test_normalized_endpoint_reuses_upload_and_detection_errors(content, filename, code):
    response = post("/api/v1/analyze/normalized", content, filename)
    assert response.status_code == code


def test_normalized_unsupported_platform_is_rejected():
    response = post("/api/v1/analyze/normalized", params={"platform": "osquery"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "unsupported_platform"


def test_normalized_explicit_mismatch_is_rejected():
    response = post(
        "/api/v1/analyze/normalized",
        "something else",
        params={"platform": "cisco_asa"},
    )
    assert response.status_code == 422


def test_normalized_payload_does_not_include_raw_configuration():
    payload = "__import__('os').system('whoami') <script>alert(1)</script>"
    config = (
        "hostname SECURITY-TEST\n"
        "interface GigabitEthernet0/0\n"
        f" description {payload}\n"
        "nameif outside\n"
        "object network HOST\n host 192.0.2.5\n"
    )
    response = post("/api/v1/analyze/normalized", config)
    assert response.status_code == 200, response.text
    body = response.json()
    assert "configuration" not in body
    assert "raw_config" not in json.dumps(body)
    assert body["platform"]["hostname"] == "SECURITY-TEST"


def test_coverage_discloses_limits_and_not_assessed_domains():
    domains = {x.domain: x.status for x in normalize_sample().coverage.domains}
    assert domains["access_control"] is CoverageStatus.ASSESSED
    assert domains["intrusion_detection_signatures"] is CoverageStatus.NOT_ASSESSED
    assert domains["runtime_traffic_detection"] is CoverageStatus.NOT_ASSESSED
    assert any("not directly comparable" in item for item in normalize_sample().coverage.limitations)


@pytest.mark.parametrize("name", ["critical", "high", "medium", "low", "info", "unknown"])
def test_severity_values_are_standardized(name):
    assert Severity(name).value == name


def test_unrecognized_severity_is_not_labeled_low():
    report = REGISTRY.get("cisco_asa").analyze(ASA.splitlines())
    if not report["findings"]:
        pytest.skip("sample generated no findings")
    modified = deepcopy(report)
    modified["findings"][0]["severity"] = "UNRECOGNIZED"
    result = normalize_cisco_asa_report(modified, DESCRIPTOR).to_dict()
    assert result["findings"][0]["severity"] == "unknown"
    assert result["summary"]["severity_counts"]["unknown"] == 1


def test_summary_rejects_inconsistent_counts():
    counts = {severity.value: 0 for severity in Severity}
    counts["high"] = 2
    with pytest.raises(ValueError, match="total_findings"):
        NormalizedSummary(total_findings=1, severity_counts=counts)


@pytest.mark.parametrize("invalid", [-1, 101, True, 3.14])
def test_summary_rejects_invalid_scores(invalid):
    with pytest.raises(ValueError):
        NormalizedSummary(
            total_findings=0,
            severity_counts={severity.value: 0 for severity in Severity},
            security_score=invalid,
        )


@pytest.mark.parametrize("bad", [0, -1, True, "10"])
def test_evidence_rejects_invalid_line_numbers(bad):
    with pytest.raises(ValueError):
        FindingEvidence(line_number=bad)


def test_ids_and_ips_are_representable_without_fabricated_scores():
    for family in (DeviceFamily.IDS, DeviceFamily.IPS):
        finding = NormalizedFinding(
            finding_id=f"sample:{family.value}:000001",
            code="TEST-001",
            severity=Severity.INFO,
            title="Example",
            description="Synthetic normalized example; no IDS was analyzed.",
            recommendation="No action.",
            evidence=FindingEvidence(),
        )
        summary = NormalizedSummary(
            total_findings=1,
            severity_counts={severity.value: int(severity is Severity.INFO) for severity in Severity},
        )
        data = NormalizedReport(
            schema_version="1.0",
            platform=PlatformIdentity("test", "Test", family),
            findings=(finding,),
            summary=summary,
            coverage=AnalysisCoverage(
                assessment_type="static_configuration",
                domains=(CoverageDomain("signatures", CoverageStatus.NOT_ASSESSED),),
                limitations=("No real analyzer was run.",),
            ),
        ).to_dict()
        assert data["platform"]["family"] == family.value
        assert data["summary"]["security_score"] is None


def test_unknown_platform_cannot_use_asa_normalizer():
    from app.core.platforms import PlatformDescriptor
    with pytest.raises(ValueError, match="Cisco ASA"):
        normalize_cisco_asa_report(
            {"findings": [], "summary": {"total_findings": 0}},
            PlatformDescriptor("snort", "Snort", DeviceFamily.IDS, (".rules",)),
        )


def test_duplicate_finding_ids_rejected():
    finding = NormalizedFinding("duplicate", "TEST-1", Severity.LOW, "Test", "", "", FindingEvidence())
    counts = {severity.value: int(severity is Severity.LOW) * 2 for severity in Severity}
    with pytest.raises(ValueError, match="duplicate finding IDs"):
        NormalizedReport(
            "1.0", PlatformIdentity("test", "Test", DeviceFamily.FIREWALL),
            NormalizedSummary(2, counts), (finding, finding),
            AnalysisCoverage("static_configuration", (), ()),
        )
