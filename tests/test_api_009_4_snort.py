"""API-009.4: Snort 2 subset parser, safe routing and normalization tests."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.analyzer.snort import analyze_snort_configuration
from app.core.adapters.snort import SnortAdapter
from app.core.catalog import create_default_registry
from app.core.detection import (
    DetectionStatus, PlatformDetectionError, detect_platform, select_platform,
)
from app.core.snort_normalization import normalize_snort_report
from app.parsers.ids.snort import SnortParser

REGISTRY = create_default_registry()
RULE = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Probe"; sid:1000001; rev:1; content:"GET";)' 
RULE_2 = 'alert tcp any any -> $HOME_NET 443 (msg:"Probe2"; sid:1000002; rev:1;)'
STRONG = 'preprocessor stream5_global: track_tcp yes\n'
CONFIG = STRONG + 'ipvar HOME_NET 192.0.2.0/24\n' + RULE + '\n'
ASA = 'hostname TEST-ASA\nobject network HOST\n host 192.0.2.5\n'


def post(endpoint, content=RULE, *, filename="example.rules", platform="snort"):
    if isinstance(content, str):
        content = content.encode("utf-8")
    params = {"platform": platform} if platform is not None else None
    with TestClient(app) as client:
        return client.post(endpoint, params=params, files={
            "file": (filename, content, "text/plain"),
        })


def test_snort_parser_extracts_sid_revision_and_message():
    config = SnortParser().parse([RULE])
    rule = config.rules[0]
    assert (rule.sid, rule.revision, rule.message, rule.enabled) == (1000001, 1, "Probe", True)


def test_quoted_semicolon_is_not_split_as_rule_option():
    rule = RULE.replace('msg:"Probe"', 'msg:"hello; world"')
    parsed = SnortParser().parse([rule]).rules[0]
    assert parsed.message == "hello; world"
    assert "sid" in parsed.option_names


def test_backtick_and_shell_looking_strings_are_not_executed():
    payload = "$(whoami) __import__('os').system('whoami') <script>"
    rule = RULE.replace('msg:"Probe"', f'msg:"{payload}"')
    parsed = SnortParser().parse([rule]).rules[0]
    assert parsed.message == payload


def test_commented_rule_is_disabled():
    parsed = SnortParser().parse(["# " + RULE])
    assert len(parsed.rules) == 1 and not parsed.rules[0].enabled


def test_ordinary_comments_do_not_create_rules():
    assert not SnortParser().parse(["# some comments", "#include xyz"]).rules


def test_malformed_rule_is_recorded_not_executed():
    config = SnortParser().parse(["alert tcp invalid syntax (sid:1;)"])
    assert config.malformed_rule_lines == (1,)


def test_invalid_sid_is_reported():
    config = SnortParser().parse([RULE.replace("sid:1000001", "sid:abc")])
    assert config.rules[0].sid is None
    assert "SNORT-001" in {f["code"] for f in analyze_snort_configuration(config)}


def test_missing_sid_is_reported():
    config = SnortParser().parse([RULE.replace("sid:1000001; ", "")])
    assert "SNORT-001" in {f["code"] for f in analyze_snort_configuration(config)}


def test_duplicate_enabled_sid_is_reported():
    config = SnortParser().parse([RULE, RULE])
    assert "SNORT-002" in {f["code"] for f in analyze_snort_configuration(config)}


def test_duplicate_with_disabled_sid_is_not_reported():
    config = SnortParser().parse([RULE, "# " + RULE])
    assert "SNORT-002" not in {f["code"] for f in analyze_snort_configuration(config)}


def test_home_net_any_is_flagged():
    config = SnortParser().parse(["ipvar HOME_NET any", RULE])
    assert "SNORT-003" in {f["code"] for f in analyze_snort_configuration(config)}


def test_missing_home_net_definition_is_not_called_disabled():
    config = SnortParser().parse([RULE])
    assert "SNORT-007" in {f["code"] for f in analyze_snort_configuration(config)}


def test_broad_pass_header_is_reported():
    config = SnortParser().parse([RULE.replace("alert tcp $EXTERNAL_NET any -> $HOME_NET 80", "pass tcp any any -> any any")])
    assert "SNORT-005" in {f["code"] for f in analyze_snort_configuration(config)}


def test_includes_not_loaded_and_no_incorrect_empty_inline_finding():
    config = SnortParser().parse(["include ../private/secret.rules"])
    assert config.includes_count == 1
    assert any("not followed" in w for w in config.warnings)
    assert "SNORT-009" not in {f["code"] for f in analyze_snort_configuration(config)}


def test_no_enabled_rules_is_qualified():
    config = SnortParser().parse(["# " + RULE])
    assert "SNORT-009" in {f["code"] for f in analyze_snort_configuration(config)}


def test_output_directive_is_recognized():
    config = SnortParser().parse(["output alert_fast: alert.fast", RULE])
    assert config.output_directives_count == 1
    assert "SNORT-010" not in {f["code"] for f in analyze_snort_configuration(config)}


def test_missing_output_is_only_informational():
    config = SnortParser().parse([RULE])
    f = next(f for f in analyze_snort_configuration(config) if f["code"] == "SNORT-010")
    assert f["severity"] == "INFO" and "does not prove" in f["description"]


def test_snort_adapter_registered_as_ids():
    descriptor = REGISTRY.get("snort").descriptor
    assert descriptor.family.value == "ids"
    assert ".rules" in descriptor.extensions


def test_snort_adapter_does_not_assign_unjustified_score():
    result = SnortAdapter().analyze(CONFIG.splitlines())
    assert result["summary"]["security_score"] is None
    assert result["summary"]["risk_level"] is None
    assert result["device_family"] == "ids"


def test_auto_detect_snort_specific_config():
    result = detect_platform(CONFIG.splitlines(), REGISTRY)
    assert result.status is DetectionStatus.SUPPORTED
    assert result.platform_id == "snort"


def test_rule_only_auto_detection_remains_conservative():
    result = detect_platform([RULE], REGISTRY)
    assert result.status is DetectionStatus.UNSUPPORTED


def test_explicit_rule_only_snort_selected():
    selection = select_platform([RULE], REGISTRY, "snort")
    assert (selection.platform_id, selection.method) == ("snort", "explicit")


def test_asa_snort_mix_rejected_ambiguous():
    with pytest.raises(PlatformDetectionError, match="conflicting"):
        select_platform((ASA + STRONG).splitlines(), REGISTRY)


def test_explicit_snort_rejects_asa_config():
    with pytest.raises(PlatformDetectionError) as exc:
        select_platform(ASA.splitlines(), REGISTRY, "snort")
    assert exc.value.code == "platform_mismatch"


def test_suricata_yaml_is_not_misclassified_as_snort():
    result = detect_platform(["rule-files:", " - local.rules"], REGISTRY)
    assert result.status is DetectionStatus.SUPPORTED
    assert result.platform_id == "suricata"


def test_api_lists_both_verified_platforms():
    with TestClient(app) as client:
        response = client.get("/api/v1/platforms")
    assert response.status_code == 200
    assert {p["platform_id"] for p in response.json()["platforms"]} == {"cisco_asa", "fortios", "snort", "suricata"}


def test_snort_rules_upload_requires_explicit_selection():
    response = post("/api/v1/analyze/universal", RULE, platform=None)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unsupported_format"


def test_explicit_snort_rules_upload_successful():
    response = post("/api/v1/analyze/universal", CONFIG, filename="example.rules")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["platform_detection"] == {"platform_id": "snort", "method": "explicit"}
    assert data["summary"]["total_rules"] == 1


def test_automatic_snort_config_upload_succeeds():
    response = post("/api/v1/analyze/universal", CONFIG, filename="snort.conf", platform=None)
    assert response.status_code == 200, response.text
    assert response.json()["platform_detection"]["method"] == "automatic"


def test_asa_file_with_rules_extension_is_rejected():
    response = post("/api/v1/analyze/universal", ASA, filename="asa.rules", platform=None)
    assert response.status_code == 400


def test_normalized_snort_endpoint_exposes_coverage_not_fake_score():
    response = post("/api/v1/analyze/normalized", CONFIG)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["platform"]["platform_id"] == "snort"
    assert data["summary"]["security_score"] is None
    assert data["summary"]["total_findings"] == len(data["findings"])
    assert data["coverage"]["assessment_type"] == "static_configuration"
    assert any(x["status"] == "not_assessed" for x in data["coverage"]["domains"])
    assert "configuration" not in data


def test_snort_normalization_is_deterministic_json():
    report = SnortAdapter().analyze(CONFIG.splitlines())
    normalized = normalize_snort_report(report, REGISTRY.get("snort").descriptor)
    assert json.loads(json.dumps(normalized.to_dict())) == normalized.to_dict()


def test_normalized_platform_rejects_wrong_descriptor():
    report = SnortAdapter().analyze(CONFIG.splitlines())
    with pytest.raises(ValueError):
        normalize_snort_report(report, REGISTRY.get("cisco_asa").descriptor)


def test_snort_normalization_rejects_inconsistent_summary():
    report = SnortAdapter().analyze(CONFIG.splitlines())
    report["summary"]["total_findings"] = 999
    with pytest.raises(ValueError):
        normalize_snort_report(report, REGISTRY.get("snort").descriptor)


@pytest.mark.parametrize("payload,filename,expected", [
    (b"", "test.rules", 400),
    (b"\xff\xfe", "test.rules", 400),
    (b"x\x00y", "test.rules", 400),
    (b"A" * (2 * 1024 * 1024 + 1), "test.rules", 413),
    (RULE, "attack.exe", 400),
    (RULE, "attack.rules.exe", 400),
], ids=[
    "empty-rules", "utf8-rejected", "nul-rejected", "oversize-rejected",
    "extension-rejected", "double-extension-rejected",
])
def test_snort_upload_validation(payload, filename, expected):
    response = post("/api/v1/analyze/universal", payload, filename=filename)
    assert response.status_code == expected


def test_untrusted_include_not_opened(monkeypatch):
    def fail_open(*args, **kwargs):
        raise AssertionError("Snort config must not open include paths")
    monkeypatch.setattr(Path, "open", fail_open)
    result = SnortAdapter().analyze(["include ../../secrets.conf", RULE])
    assert result["summary"]["include_directives"] == 1


def test_legacy_asa_upload_still_works():
    response = post("/api/v1/analyze", ASA, filename="asa.conf", platform=None)
    assert response.status_code == 200, response.text
    assert response.json()["vendor"] == "Cisco ASA"
