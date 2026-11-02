"""API-009.1: non-breaking universal platform architecture regression tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.core.adapters.cisco_asa import CiscoASAAdapter
from app.core.catalog import create_default_registry
from app.core.platforms import DeviceFamily, PlatformDescriptor
from app.core.registry import PlatformRegistry, UnsupportedPlatformError


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "configs" / "firewall.conf"


class FakeAdapter:
    descriptor = PlatformDescriptor(
        platform_id="test_ids",
        display_name="Test IDS",
        family=DeviceFamily.IDS,
        extensions=(".rules",),
    )

    def __init__(self) -> None:
        self.calls = 0

    def analyze(self, lines: list[str]) -> dict:
        self.calls += 1
        return {"lines": list(lines)}


def test_registry_starts_empty():
    assert PlatformRegistry().list_platforms() == ()


def test_default_registry_contains_four_verified_platforms():
    registry = create_default_registry()
    entries = registry.list_platforms()
    assert len(entries) == 4
    assert entries[0].platform_id == "cisco_asa"
    assert entries[1].platform_id == "fortios"
    assert entries[1].family is DeviceFamily.FIREWALL
    assert entries[2].platform_id == "snort"
    assert entries[2].family is DeviceFamily.IDS
    assert entries[3].platform_id == "suricata"
    assert entries[3].family is DeviceFamily.IDS
    assert entries[0].display_name == "Cisco ASA"
    assert entries[0].family is DeviceFamily.FIREWALL


def test_default_registry_returns_cisco_asa_adapter():
    assert isinstance(create_default_registry().get("cisco_asa"), CiscoASAAdapter)


def test_lookup_normalizes_case_and_surrounding_space():
    registry = create_default_registry()
    assert registry.get("  CISCO_ASA  ") is registry.get("cisco_asa")


@pytest.mark.parametrize("unknown", ["zeek", "osquery", "palo_alto", "../../etc", ""])
def test_unimplemented_platform_is_not_silently_accepted(unknown):
    with pytest.raises(UnsupportedPlatformError):
        create_default_registry().get(unknown)


def test_registry_rejects_non_string_lookup():
    with pytest.raises(TypeError):
        create_default_registry().get(None)  # type: ignore[arg-type]


def test_registry_rejects_duplicate_platform():
    registry = PlatformRegistry()
    adapter = FakeAdapter()
    registry.register(adapter)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(FakeAdapter())


def test_registry_rejects_missing_descriptor():
    registry = PlatformRegistry()
    with pytest.raises(TypeError):
        registry.register(object())  # type: ignore[arg-type]


def test_registry_rejects_adapter_without_analyze():
    class Incomplete:
        descriptor = FakeAdapter.descriptor

    with pytest.raises(TypeError):
        PlatformRegistry().register(Incomplete())  # type: ignore[arg-type]


def test_registration_does_not_execute_analyzer():
    adapter = FakeAdapter()
    registry = PlatformRegistry()
    registry.register(adapter)
    assert adapter.calls == 0
    assert registry.get("test_ids").analyze(["raw data"]) == {"lines": ["raw data"]}
    assert adapter.calls == 1


def test_registry_lists_platforms_in_deterministic_order():
    registry = PlatformRegistry()
    registry.register(FakeAdapter())
    registry.register(CiscoASAAdapter())
    assert [item.platform_id for item in registry.list_platforms()] == [
        "cisco_asa", "test_ids"
    ]


@pytest.mark.parametrize("bad_id", ["", "Cisco ASA", "../bad", "UPPER", "9leading", "x" * 65])
def test_descriptor_rejects_invalid_platform_ids(bad_id):
    with pytest.raises(ValueError):
        PlatformDescriptor(bad_id, "Invalid", DeviceFamily.IDS, (".conf",))


def test_descriptor_rejects_invalid_file_suffix():
    with pytest.raises(ValueError):
        PlatformDescriptor("test_ids", "IDS", DeviceFamily.IDS, ("*.conf",))


def test_descriptor_rejects_blank_name():
    with pytest.raises(ValueError):
        PlatformDescriptor("test_ids", " ", DeviceFamily.IDS, (".conf",))


def test_cisco_asa_adapter_does_not_change_existing_api_report():
    """Compare actual endpoint output to adapter output for stable fields."""
    lines = [
        "hostname API-009-TEST",
        "interface GigabitEthernet0/0",
        " description a harmless string",
        "!",
    ]
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            files={"file": ("example.conf", "\n".join(lines).encode(), "text/plain")},
        )
    assert response.status_code == 200, response.text
    legacy = response.json()
    adapted = create_default_registry().get("cisco_asa").analyze(lines)
    for field in ("vendor", "hostname", "summary", "findings", "warnings", "configuration"):
        assert adapted[field] == legacy[field], field


def test_cisco_asa_adapter_preserves_untrusted_interface_text():
    payload = "__import__('os').system('whoami') <script>alert(1)</script>"
    lines = ["hostname TEST-ASA", "interface GigabitEthernet0/0", f" description {payload}"]
    result = CiscoASAAdapter().analyze(lines)
    assert result["configuration"]["interfaces"][0]["description"] == payload


def test_cisco_asa_sample_report_regression():
    assert SAMPLE.is_file(), f"Missing sample: {SAMPLE}"
    lines = SAMPLE.read_text(encoding="utf-8-sig").splitlines()
    result = CiscoASAAdapter().analyze(lines)
    assert result["vendor"] == "Cisco ASA"
    assert result["hostname"] == "ASA-FIREWALL"
    assert result["summary"]["security_score"] == 21
    assert result["summary"]["total_findings"] == 29
    assert len(result["configuration"]["rules"]) == 9


def test_original_upload_endpoint_still_works():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            files={"file": ("simple.conf", b"hostname TEST-ASA\n", "text/plain")},
        )
    assert response.status_code == 200, response.text
    assert response.json()["hostname"] == "TEST-ASA"
