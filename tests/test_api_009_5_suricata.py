"""API-009.5: Suricata static subset, safe upload/routing, normalization."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.analyzer.suricata import analyze_suricata_configuration
from app.core.adapters.suricata import SuricataAdapter
from app.core.catalog import create_default_registry
from app.core.detection import (
    DetectionStatus, PlatformDetectionError, detect_platform, select_platform,
)
from app.core.suricata_normalization import normalize_suricata_report
from app.parsers.ids.suricata import SuricataParser

REGISTRY = create_default_registry()
RULE = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP; probe"; sid:2000001; rev:2; content:"GET";)'
SECOND = 'drop tcp any any -> $HOME_NET 443 (msg:"Drop"; gid:2; sid:2000002; rev:1;)'
YAML = """%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.0.2.0/24]"
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
outputs:
  - eve-log:
      enabled: yes
af-packet:
  - interface: eth0
"""
ASA = "hostname ASA\nobject network SERVER\n host 192.0.2.12\n"
SNORT = "preprocessor stream5_global: track_tcp yes\n"


def post(endpoint="/api/v1/analyze/universal", content=YAML, *, filename="suricata.yaml", platform=None):
    if isinstance(content, str):
        content = content.encode("utf-8")
    params = {"platform": platform} if platform is not None else None
    with TestClient(app) as client:
        return client.post(endpoint, params=params, files={
            "file": (filename, content, "application/octet-stream"),
        })


def codes(config):
    return {item["code"] for item in analyze_suricata_configuration(config)}


def test_registry_lists_suricata():
    assert [d.platform_id for d in REGISTRY.list_platforms()] == ["cisco_asa", "fortios", "snort", "suricata"]


def test_suricata_is_ids_family_with_yaml_rules_extensions():
    d = REGISTRY.get("suricata").descriptor
    assert d.family.value == "ids"
    assert {".yaml", ".yml", ".rules"}.issubset(d.extensions)


def test_parser_extracts_rule_header_sid_gid_rev():
    rule = SuricataParser().parse([SECOND]).rules[0]
    assert (rule.action, rule.protocol, rule.sid, rule.gid, rule.revision) == ("drop", "tcp", 2000002, 2, 1)


def test_gid_defaults_to_one():
    assert SuricataParser().parse([RULE]).rules[0].gid == 1


def test_option_semicolon_inside_quotes_does_not_break():
    assert SuricataParser().parse([RULE]).rules[0].sid == 2000001


def test_comment_rules_are_disabled():
    parsed = SuricataParser().parse(["# " + RULE])
    assert len(parsed.rules) == 1 and parsed.rules[0].enabled is False


def test_regular_comment_is_ignored():
    assert not SuricataParser().parse(["# I am a comment", "#include evil"]).rules


def test_missing_sid_is_reported():
    assert "SURICATA-001" in codes(SuricataParser().parse([RULE.replace("sid:2000001;", "")]))


@pytest.mark.parametrize("bad", ["invalid", "0", "-1", "9999999999999999999"], ids=["letters", "zero", "negative", "huge"])
def test_invalid_sid_is_reported(bad):
    assert "SURICATA-001" in codes(SuricataParser().parse([RULE.replace("sid:2000001", f"sid:{bad}")]))


def test_duplicate_gid_sid_pair_is_reported():
    assert "SURICATA-002" in codes(SuricataParser().parse([RULE, RULE]))


def test_same_sid_different_gid_not_duplicate():
    other = RULE.replace("sid:2000001", "gid:2; sid:2000001")
    assert "SURICATA-002" not in codes(SuricataParser().parse([RULE, other]))


def test_disabled_rule_does_not_cause_duplicate():
    assert "SURICATA-002" not in codes(SuricataParser().parse([RULE, "# " + RULE]))


def test_disabled_rule_has_info_finding():
    assert "SURICATA-004" in codes(SuricataParser().parse(["# " + RULE]))


def test_bad_header_produces_malformed_line():
    c = SuricataParser().parse(["alert tcp broken header (sid:1;)"])
    assert c.malformed_rule_lines == (1,)
    assert "SURICATA-008" in codes(c)


def test_broad_pass_rule_is_qualified():
    c = SuricataParser().parse(['pass ip any any -> any any (msg:"test"; sid:123;)'])
    assert "SURICATA-005" in codes(c)


def test_broad_ip_alert_rule_is_qualified():
    c = SuricataParser().parse(['alert ip any any -> any any (msg:"test"; sid:123;)'])
    assert "SURICATA-006" in codes(c)


def test_rejectsrc_suricata_action():
    c = SuricataParser().parse(['rejectsrc tcp any any -> any 80 (msg:"t"; sid:123;)'])
    assert c.rules[0].action == "rejectsrc"


def test_yaml_extracts_restricted_settings():
    c = SuricataParser().parse(YAML.splitlines())
    assert c.home_net == "[192.0.2.0/24]"
    assert c.rule_file_count == 1
    assert c.eve_log_enabled is True
    assert c.af_packet_interfaces == 1
    assert c.yaml_recognized


def test_yaml_home_net_any_finding():
    c = SuricataParser().parse((YAML.replace("[192.0.2.0/24]", "any")).splitlines())
    assert "SURICATA-003" in codes(c)


def test_yaml_disabled_eve_finding():
    c = SuricataParser().parse(YAML.replace("enabled: yes", "enabled: no").splitlines())
    assert c.eve_log_enabled is False
    assert "SURICATA-010" in codes(c)


def test_yaml_with_no_eve_setting_has_info_not_disabled_finding():
    c = SuricataParser().parse(["rule-files:", "  - local.rules"])
    assert "SURICATA-011" in codes(c)
    assert "SURICATA-010" not in codes(c)


def test_rule_files_not_loaded_or_counted_as_inline_rules(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Upload parser must never open rule-file references")
    monkeypatch.setattr(Path, "open", fail)
    c = SuricataParser().parse(["rule-files:", "  - ../../secrets.rules"])
    assert c.rule_file_count == 1 and len(c.rules) == 0
    assert any("not opened" in warning for warning in c.warnings)
    assert "SURICATA-009" not in codes(c)


def test_empty_rule_set_is_qualified():
    assert "SURICATA-009" in codes(SuricataParser().parse([]))


def test_home_net_not_visible_is_only_info():
    c = SuricataParser().parse([RULE])
    f = next(x for x in analyze_suricata_configuration(c) if x["code"] == "SURICATA-007")
    assert f["severity"] == "INFO"


def test_malicious_text_preserved_as_plain_data_not_executed():
    injection = "$(whoami) __import__('os').system('whoami')"
    c = SuricataParser().parse([RULE.replace("HTTP; probe", injection)])
    assert len(c.rules) == 1


def test_unsafe_yaml_tags_are_not_deserialized():
    c = SuricataParser().parse(["rule-files:", "  - !!python/object/apply:os.system [whoami]"])
    assert c.yaml_recognized
    assert c.rule_file_count == 0
    assert any("outside" in warning for warning in c.warnings)


def test_adapter_has_no_numeric_unvalidated_score():
    report = SuricataAdapter().analyze(YAML.splitlines())
    assert report["summary"]["security_score"] is None
    assert report["summary"]["risk_level"] is None
    assert report["device_family"] == "ids"


def test_adapter_summary_matches_findings():
    report = SuricataAdapter().analyze([RULE, RULE])
    assert report["summary"]["total_findings"] == len(report["findings"])
    assert report["summary"]["total_rules"] == 2


def test_automatic_suricata_detection_yaml():
    result = detect_platform(YAML.splitlines(), REGISTRY)
    assert (result.status, result.platform_id) == (DetectionStatus.SUPPORTED, "suricata")


def test_automatic_snort_detection_unchanged():
    assert detect_platform(SNORT.splitlines(), REGISTRY).platform_id == "snort"


def test_automatic_asa_detection_unchanged():
    assert detect_platform(ASA.splitlines(), REGISTRY).platform_id == "cisco_asa"


def test_isolated_rule_never_auto_detects_suricata_or_snort():
    assert detect_platform([RULE], REGISTRY).status is DetectionStatus.UNSUPPORTED


def test_explicit_rule_only_suricata():
    selection = select_platform([RULE], REGISTRY, "suricata")
    assert (selection.platform_id, selection.method) == ("suricata", "explicit")


@pytest.mark.parametrize("bad", ["zeek", "unknown", "../suricata"], ids=["zeek", "unknown", "path"])
def test_truly_unsupported_platform_rejected(bad):
    with pytest.raises(PlatformDetectionError) as exc:
        select_platform(YAML.splitlines(), REGISTRY, bad)
    assert exc.value.code == "unsupported_platform"


def test_explicit_suricata_rejects_snort_config():
    with pytest.raises(PlatformDetectionError) as exc:
        select_platform(SNORT.splitlines(), REGISTRY, "suricata")
    assert exc.value.code == "platform_mismatch"


def test_explicit_suricata_rejects_asa():
    with pytest.raises(PlatformDetectionError) as exc:
        select_platform(ASA.splitlines(), REGISTRY, "suricata")
    assert exc.value.code == "platform_mismatch"


def test_snort_suricata_strong_markers_conflict():
    result = detect_platform((SNORT + YAML).splitlines(), REGISTRY)
    assert result.status is DetectionStatus.AMBIGUOUS


def test_api_lists_three_platforms():
    with TestClient(app) as client:
        response = client.get("/api/v1/platforms")
    assert response.status_code == 200
    assert {p["platform_id"] for p in response.json()["platforms"]} == {"cisco_asa", "fortios", "snort", "suricata"}


def test_api_suricata_yaml_automatic_success():
    response = post()
    assert response.status_code == 200, response.text
    assert response.json()["platform_detection"] == {"platform_id": "suricata", "method": "automatic"}


def test_api_suricata_yml_success():
    response = post(filename="config.yml")
    assert response.status_code == 200, response.text


def test_api_rules_suricata_explicit_success():
    response = post(content=RULE, filename="local.rules", platform="suricata")
    assert response.status_code == 200, response.text
    assert response.json()["summary"]["total_rules"] == 1


def test_api_rules_no_automatic_guess():
    response = post(content=RULE, filename="local.rules")
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unsupported_format"


def test_api_explicit_snort_cannot_override_suricata_yaml():
    response = post(platform="snort")
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "platform_mismatch"


def test_api_asa_with_yaml_extension_rejected():
    response = post(content=ASA, platform="cisco_asa")
    assert response.status_code == 400


def test_api_normalized_suricata_yaml_success():
    response = post("/api/v1/analyze/normalized")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["platform"]["platform_id"] == "suricata"
    assert data["platform"]["detection_method"] == "automatic"
    assert data["summary"]["security_score"] is None
    assert data["summary"]["total_findings"] == len(data["findings"])
    assert "configuration" not in data
    assert any(x["status"] == "not_assessed" for x in data["coverage"]["domains"])


def test_api_normalized_suricata_rules_success():
    response = post("/api/v1/analyze/normalized", RULE, filename="local.rules", platform="suricata")
    assert response.status_code == 200, response.text
    assert response.json()["platform"]["detection_method"] == "explicit"


def test_normalizer_deterministic_json():
    report = SuricataAdapter().analyze([RULE, RULE])
    normalized = normalize_suricata_report(report, REGISTRY.get("suricata").descriptor)
    assert json.loads(json.dumps(normalized.to_dict())) == normalized.to_dict()


def test_normalizer_rejects_wrong_platform():
    report = SuricataAdapter().analyze([RULE])
    with pytest.raises(ValueError):
        normalize_suricata_report(report, REGISTRY.get("snort").descriptor)


def test_normalizer_rejects_inconsistent_count():
    report = SuricataAdapter().analyze([RULE])
    report["summary"]["total_findings"] += 1
    with pytest.raises(ValueError):
        normalize_suricata_report(report, REGISTRY.get("suricata").descriptor)


@pytest.mark.parametrize("payload,filename,status", [
    (b"", "suricata.yaml", 400),
    (b"\xff\xff", "suricata.yaml", 400),
    (b"a\x00b", "suricata.yaml", 400),
    (b"A" * (2 * 1024 * 1024 + 1), "suricata.yaml", 413),
    (YAML, "suricata.exe", 400),
    (YAML, "config.yaml.exe", 400),
    (YAML, "config.noext", 400),
], ids=[
    "empty-yaml", "invalid-utf8-yaml", "nul-yaml", "oversize-yaml",
    "extension-exe", "double-extension", "unknown-extension",
])
def test_api_yaml_upload_validation(payload, filename, status):
    result = post(content=payload, filename=filename)
    assert result.status_code == status, result.text


def test_normalized_api_rejects_unknown_platform():
    response = post("/api/v1/analyze/normalized", platform="zeek")
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "unsupported_platform"
