"""API-009.9 IDS bundle tests; does not require running the web server."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.core.ids_bundle import analyze_ids_rule_bundle

S1 = 'alert tcp any any -> any 80 (msg:"One"; sid:1001; rev:1;)\n'
S2 = 'alert tcp any any -> any 443 (msg:"Two"; sid:1001; rev:2;)\n'
SUR1 = 'alert tcp any any -> any 80 (msg:"One"; sid:1001; gid:1;)\n'
SUR2 = 'alert tcp any any -> any 80 (msg:"Two"; sid:1001; gid:2;)\n'
CONFIG = '''suricata-version: "8.0"
rule-files:
  - first.rules
  - /etc/suricata/rules/missing.rules
vars:
  address-groups:
    HOME_NET: "[192.0.2.0/24]"
outputs:
  - eve-log:
      enabled: yes
'''
SNORT_CONFIG = 'preprocessor stream5_global: track_tcp yes\ninclude /opt/snort/rules/first.rules\n'


def upload(*, platform="suricata", rule_files=None, config=None):
    rule_files = rule_files if rule_files is not None else [("first.rules", SUR1)]
    parts = [("rules", (name, data.encode() if isinstance(data, str) else data, "application/octet-stream"))
             for name, data in rule_files]
    if config is not None:
        name, content = config
        parts.append(("config", (name, content.encode() if isinstance(content, str) else content, "text/plain")))
    with TestClient(app) as client:
        return client.post("/api/v1/analyze/ids-bundle", params={"platform": platform}, files=parts)


def test_registered_endpoint_visible_in_openapi():
    assert "/api/v1/analyze/ids-bundle" in app.openapi()["paths"]


def test_suricata_upload_without_config():
    response = upload()
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["platform"]["platform_id"] == "suricata"
    assert result["summary"]["rule_files_uploaded"] == 1
    assert result["summary"]["enabled_rules_visible"] == 1
    assert result["summary"]["security_score"] is None
    assert result["coverage"]["runtime_detection"] == "not_assessed"


def test_snort_upload_with_config():
    response = upload(platform="snort", rule_files=[("first.rules", S1)], config=("snort.conf", SNORT_CONFIG))
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["platform"]["platform_id"] == "snort"
    assert result["coverage"]["referenced_files"]["filename_candidate_matches"] == 1
    assert result["summary"]["files_inspected"] == 2


def test_suricata_yaml_refs_are_inert_filename_candidates_only():
    response = upload(config=("suricata.yaml", CONFIG))
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["coverage"]["referenced_files"] == {
        "entries_visible": 2, "filename_candidate_matches": 1, "not_uploaded": 1, "identity_verified": False,
    }
    assert result["summary"]["total_findings"] == 0
    assert any("not supplied" in message for message in result["warnings"])


def test_duplicate_sid_detected_across_snort_files():
    response = upload(platform="snort", rule_files=[("first.rules", S1), ("second.rules", S2)])
    assert response.status_code == 200, response.text
    findings = [item for item in response.json()["findings"] if item["code"] == "IDS-BUNDLE-001"]
    assert len(findings) == 1
    assert findings[0]["evidence"]["filename"] == "second.rules"
    assert findings[0]["evidence"]["related_filename"] == "first.rules"


def test_duplicate_gid_sid_across_suricata_sources():
    response = upload(rule_files=[("first.rules", SUR1), ("second.rules", SUR1)])
    assert response.status_code == 200
    assert any(f["code"] == "IDS-BUNDLE-001" for f in response.json()["findings"])


def test_suricata_same_sid_different_gid_is_not_duplicate():
    response = upload(rule_files=[("first.rules", SUR1), ("second.rules", SUR2)])
    assert response.status_code == 200
    assert not any(f["code"] == "IDS-BUNDLE-001" for f in response.json()["findings"])


def test_disabled_rule_not_duplicate():
    response = upload(platform="snort", rule_files=[("first.rules", S1), ("second.rules", "# " + S1)])
    assert response.status_code == 200
    assert not any(f["code"] == "IDS-BUNDLE-001" for f in response.json()["findings"])


def test_suricata_yaml_comments_do_not_create_false_findings():
    response = upload(config=("suricata.yaml", CONFIG + "# Log the raw rule text.\n# Log TCP data after normalization\n"))
    assert response.status_code == 200, response.text
    assert response.json()["summary"]["total_findings"] == 0


def test_malformed_active_rule_reported_with_file_provenance():
    response = upload(rule_files=[("first.rules", 'alert tcp any any -> any 80 (msg:"missing sid"; bad option;)\n')])
    assert response.status_code == 200
    assert any(f["code"] == "SURICATA-008" and f["evidence"]["filename"] == "first.rules"
               for f in response.json()["findings"])


@pytest.mark.parametrize("name", ["bad.exe", "../../secret.rules", "dir\\bad.rules"])
def test_reject_bad_rule_filenames(name):
    assert upload(rule_files=[(name, SUR1)]).status_code == 400


def test_duplicate_filenames_rejected_case_insensitive():
    assert upload(rule_files=[("a.rules", SUR1), ("A.rules", SUR2)]).status_code == 400


def test_reject_bad_configuration_extension():
    assert upload(config=("config.exe", CONFIG)).status_code == 400


def test_reject_platform_mismatch_asa_conf():
    resp = upload(config=("asa.conf", 'object network LAN\n host 192.0.2.2\n'))
    assert resp.status_code == 422


def test_reject_snort_with_yaml_config():
    assert upload(platform="snort", rule_files=[("first.rules", S1)], config=("snort.yaml", CONFIG)).status_code == 400


def test_large_individual_file_rejected():
    assert upload(rule_files=[("big.rules", b"A" * (2*1024*1024 + 1))]).status_code == 413


def test_total_size_limit_rejected():
    huge = (b"#" + b"A" * 6998 + b"\n") * 200
    # Valid individual uploads but aggregate exceeds 4 MiB.
    assert upload(rule_files=[("a.rules", huge), ("b.rules", huge), ("c.rules", huge)]).status_code == 413


def test_invalid_utf8_rejected():
    assert upload(rule_files=[("bad.rules", b"\xff\xff")]).status_code == 400


def test_too_many_rule_files_rejected():
    files = [(f"{n}.rules", SUR1) for n in range(9)]
    assert upload(rule_files=files).status_code == 400


def test_unsupported_platform_selection_rejected():
    assert upload(platform="cisco_asa").status_code == 422


def test_missing_rules_rejected():
    with TestClient(app) as client:
        result = client.post("/api/v1/analyze/ids-bundle", params={"platform": "snort"}, files={
            "config": ("snort.conf", SNORT_CONFIG, "text/plain")
        })
    assert result.status_code == 422


def test_legacy_analysis_responses_not_modified():
    with TestClient(app) as client:
        assert client.get("/").json()["version"] == "1.0.0"
        assert "/api/v1/analyze/assessment" in app.openapi()["paths"]
        assert "/api/v1/analyze/normalized" in app.openapi()["paths"]


def test_all_severity_counts_match_findings():
    report = upload(platform="snort", rule_files=[("a.rules", S1), ("b.rules", S2)]).json()
    assert sum(report["summary"]["severity_counts"].values()) == len(report["findings"])


def test_references_never_opened(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Referenced filesystem path was accessed")
    monkeypatch.setattr(Path, "open", forbidden)
    report = analyze_ids_rule_bundle(platform="suricata", rule_files=[("first.rules", SUR1.splitlines())],
        config=("suricata.yaml", CONFIG.splitlines()))
    assert report["coverage"]["referenced_files"]["entries_visible"] == 2


def test_rule_bundle_core_rejects_firewall():
    with pytest.raises(ValueError):
        analyze_ids_rule_bundle(platform="fortios", rule_files=[("f.rules", S1.splitlines())])


def test_empty_core_bundle_rejected():
    with pytest.raises(ValueError):
        analyze_ids_rule_bundle(platform="snort", rule_files=[])


def test_filename_validator_rejects_control_characters_directly():
    from app.api.ids_bundle import _safe_filename
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as caught:
        _safe_filename("evil\x00.rules")
    assert caught.value.status_code == 400


def test_snort_comment_words_do_not_become_active_rule_issues():
    response = upload(platform="snort", rule_files=[
        ("first.rules", "# Log the raw rule text.\n" + S1),
    ])
    assert response.status_code == 200
    assert not any(f["code"] == "SNORT-008" for f in response.json()["findings"])
