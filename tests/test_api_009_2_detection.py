"""API-009.2 automatic detection and explicit selection security tests."""

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.core.catalog import create_default_registry
from app.core.detection import (
    DetectionStatus,
    PlatformDetectionError,
    detect_platform,
    select_platform,
)

REGISTRY = create_default_registry()

ASA_CONFIG = """hostname TEST-ASA
object network TEST-SERVER
 host 192.0.2.5
access-list OUTSIDE extended permit tcp any any eq 443
"""
IDS_RULE = 'alert tcp any any -> $HOME_NET 80 (msg:"sample"; sid:1000001; rev:1;)'


def upload(content: bytes | str, filename: str = "input.conf", platform=None):
    if isinstance(content, str):
        content = content.encode("utf-8")
    params = {"platform": platform} if platform is not None else None
    with TestClient(app) as client:
        return client.post(
            "/api/v1/analyze/universal",
            params=params,
            files={"file": (filename, content, "text/plain")},
        )


def test_supported_platforms_endpoint_lists_verified_adapters():
    with TestClient(app) as client:
        response = client.get("/api/v1/platforms")
    assert response.status_code == 200
    entries = {p["platform_id"]: p for p in response.json()["platforms"]}
    assert set(entries) == {"cisco_asa", "fortios", "snort", "suricata"}
    assert entries["cisco_asa"] == {
        "platform_id": "cisco_asa",
        "display_name": "Cisco ASA",
        "family": "firewall",
        "extensions": [".conf", ".cfg", ".txt"],
    }
    assert entries["snort"]["family"] == "ids"
    assert ".rules" in entries["snort"]["extensions"]
    assert entries["suricata"]["family"] == "ids"
    assert ".yaml" in entries["suricata"]["extensions"]
    assert entries["fortios"]["family"] == "firewall"
    assert ".conf" in entries["fortios"]["extensions"]


def test_auto_detect_cisco_access_list():
    result = detect_platform(["access-list OUTSIDE extended permit ip any any"], REGISTRY)
    assert result.status is DetectionStatus.SUPPORTED
    assert result.platform_id == "cisco_asa"


def test_auto_detect_object_network():
    assert select_platform(["object network HOST"], REGISTRY).platform_id == "cisco_asa"


def test_weak_hostname_not_automatically_identified():
    assert detect_platform(["hostname TEST"], REGISTRY).status is DetectionStatus.UNKNOWN


def test_explicit_asa_permits_minimal_hostname():
    result = select_platform(["hostname TEST"], REGISTRY, "cisco_asa")
    assert result.method == "explicit"


@pytest.mark.parametrize("requested", ["zeek", "osquery", "../../tmp", "", "palo_alto"])
def test_unregistered_platform_rejected(requested):
    with pytest.raises(PlatformDetectionError) as error:
        select_platform(ASA_CONFIG.splitlines(), REGISTRY, requested)
    assert error.value.code == "unsupported_platform"


@pytest.mark.parametrize("line", [
    "# object network IGNORE",
    "! access-list OUTSIDE extended permit ip any any",
    "description access-list OUTSIDE extended permit ip any any",
    "SELECT * FROM users; DROP TABLE users;",
    "hostname MAYBE-CISCO",
    "interface eth0",
])
def test_no_false_positive_from_generic_or_commented_text(line):
    assert detect_platform([line], REGISTRY).status is DetectionStatus.UNKNOWN


def test_ids_signature_not_misclassified_as_cisco():
    assert detect_platform([IDS_RULE], REGISTRY).status is DetectionStatus.UNSUPPORTED


def test_ids_yaml_detects_registered_suricata():
    result = detect_platform(["rule-files:", " - local.rules"], REGISTRY)
    assert result.status is DetectionStatus.SUPPORTED
    assert result.platform_id == "suricata"


def test_conflicting_asa_and_ids_markers_is_ambiguous():
    result = detect_platform(["object network HOST", IDS_RULE], REGISTRY)
    assert result.status is DetectionStatus.AMBIGUOUS


def test_explicit_asa_cannot_override_conflicting_ids():
    with pytest.raises(PlatformDetectionError) as error:
        select_platform(["object network HOST", IDS_RULE], REGISTRY, "cisco_asa")
    assert error.value.code == "ambiguous_configuration"


def test_explicit_asa_rejects_unrecognized_content():
    with pytest.raises(PlatformDetectionError) as error:
        select_platform(["SELECT * FROM users"], REGISTRY, "cisco_asa")
    assert error.value.code == "platform_mismatch"


def test_api_automatic_asa_works():
    response = upload(ASA_CONFIG)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["hostname"] == "TEST-ASA"
    assert data["platform_detection"] == {"platform_id": "cisco_asa", "method": "automatic"}
    assert "summary" in data and "configuration" in data


def test_api_explicit_minimal_asa_works():
    response = upload("hostname MINIMAL-ASA\n", platform="cisco_asa")
    assert response.status_code == 200, response.text
    assert response.json()["platform_detection"]["method"] == "explicit"


def test_api_weak_hostname_without_selection_rejected():
    response = upload("hostname MINIMAL-ASA\n")
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unknown_format"


def test_api_snort_rule_rejected():
    response = upload(IDS_RULE)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unsupported_format"


def test_api_mixed_content_rejected():
    response = upload(ASA_CONFIG + "\n" + IDS_RULE)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "ambiguous_configuration"


def test_api_explicit_unsupported_platform_rejected():
    response = upload(ASA_CONFIG, platform="osquery")
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "unsupported_platform"


def test_api_explicit_mismatch_rejected():
    response = upload("random configuration that is not asa", platform="cisco_asa")
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "platform_mismatch"


@pytest.mark.parametrize("filename", ["bad.exe", "bad.conf.exe", "no_extension", "data.rules"])
def test_api_invalid_extensions_rejected(filename):
    response = upload(ASA_CONFIG, filename)
    assert response.status_code == 400


def test_api_oversize_rejected():
    response = upload(b"x" * (2 * 1024 * 1024 + 1))
    assert response.status_code == 413


def test_api_malformed_utf8_rejected():
    response = upload(b"object network HOST\n\xff")
    assert response.status_code == 400


def test_api_malicious_looking_description_kept_as_data():
    malicious = "__import__('os').system('whoami') <script>alert(1)</script>"
    config = f"hostname TEST-ASA\ninterface GigabitEthernet0/0\n description {malicious}\nnameif outside\n"
    response = upload(config)
    assert response.status_code == 200, response.text
    interfaces = response.json()["configuration"]["interfaces"]
    assert interfaces[0]["description"] == malicious


def test_legacy_api_unchanged_for_asa():
    with TestClient(app) as client:
        legacy = client.post(
            "/api/v1/analyze",
            files={"file": ("asa.conf", ASA_CONFIG.encode(), "text/plain")},
        )
    universal = upload(ASA_CONFIG)
    assert legacy.status_code == universal.status_code == 200
    payload = universal.json()
    payload.pop("platform_detection")
    assert payload == legacy.json()
