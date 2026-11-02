"""Migrate only the old tests whose platform-support expectations changed.

API-009.1/2/3 intentionally treated Snort as unsupported. Snort is now an
implemented adapter. This updates those assertions, not security tests.

Run from project root:
    python scripts/update_api_009_4_legacy_tests.py

All replacements are verified before any file is written. Backups are kept.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"


def replacement(path: str, old: str, new: str):
    return path, old, new


UPDATES = [
    replacement(
        "test_api_009_1_architecture.py",
        "def test_default_registry_contains_only_verified_cisco_asa():",
        "def test_default_registry_contains_verified_cisco_asa_and_snort():",
    ),
    replacement(
        "test_api_009_1_architecture.py",
        "    assert len(entries) == 1\n    assert entries[0].platform_id == \"cisco_asa\"",
        "    assert len(entries) == 2\n    assert entries[0].platform_id == \"cisco_asa\"\n"
        "    assert entries[1].platform_id == \"snort\"\n"
        "    assert entries[1].family is DeviceFamily.IDS",
    ),
    replacement(
        "test_api_009_1_architecture.py",
        '@pytest.mark.parametrize("unknown", ["snort", "suricata", "palo_alto", "../../etc", ""])',
        '@pytest.mark.parametrize("unknown", ["zeek", "suricata", "palo_alto", "../../etc", ""])',
    ),
    replacement(
        "test_api_009_2_detection.py",
        "def test_supported_platforms_endpoint_lists_only_cisco():",
        "def test_supported_platforms_endpoint_lists_verified_adapters():",
    ),
    replacement(
        "test_api_009_2_detection.py",
        '''    assert response.json()["platforms"] == [
        {
            "platform_id": "cisco_asa",
            "display_name": "Cisco ASA",
            "family": "firewall",
            "extensions": [".conf", ".cfg", ".txt"],
        }
    ]''',
        '''    entries = {p["platform_id"]: p for p in response.json()["platforms"]}
    assert set(entries) == {"cisco_asa", "snort"}
    assert entries["cisco_asa"] == {
        "platform_id": "cisco_asa",
        "display_name": "Cisco ASA",
        "family": "firewall",
        "extensions": [".conf", ".cfg", ".txt"],
    }
    assert entries["snort"]["family"] == "ids"
    assert ".rules" in entries["snort"]["extensions"]''',
    ),
    replacement(
        "test_api_009_2_detection.py",
        '@pytest.mark.parametrize("requested", ["snort", "suricata", "../../tmp", "", "palo_alto"])',
        '@pytest.mark.parametrize("requested", ["zeek", "suricata", "../../tmp", "", "palo_alto"])',
    ),
    replacement(
        "test_api_009_2_detection.py",
        '''def test_api_explicit_unsupported_platform_rejected():
    response = upload(ASA_CONFIG, platform="snort")''',
        '''def test_api_explicit_unsupported_platform_rejected():
    response = upload(ASA_CONFIG, platform="suricata")''',
    ),
    replacement(
        "test_api_009_3_normalized.py",
        '''def test_normalized_unsupported_platform_is_rejected():
    response = post("/api/v1/analyze/normalized", params={"platform": "snort"})''',
        '''def test_normalized_unsupported_platform_is_rejected():
    response = post("/api/v1/analyze/normalized", params={"platform": "suricata"})''',
    ),
]


def main():
    candidates: dict[Path, str] = {}
    for name, old, new in UPDATES:
        path = TESTS / name
        if path not in candidates:
            candidates[path] = path.read_text(encoding="utf-8")
        text = candidates[path]
        # Permit the script to be re-run after a successful migration.
        if old not in text and new in text:
            continue
        if text.count(old) != 1:
            raise RuntimeError(f"Refusing to edit {path}: expected old text exactly once")
        candidates[path] = text.replace(old, new, 1)
    # Check every backup destination before writing any files.
    pending = []
    for path, modified in candidates.items():
        previous = path.read_text(encoding="utf-8")
        if previous == modified:
            print(f"Already current: {path.name}")
            continue
        backup = path.with_suffix(path.suffix + ".api0094.bak")
        if backup.exists():
            raise RuntimeError(f"Backup already exists; refusing overwrite: {backup}")
        pending.append((path, previous, modified, backup))
    for path, previous, modified, backup in pending:
        backup.write_text(previous, encoding="utf-8")
        path.write_text(modified, encoding="utf-8")
        print(f"Updated: {path.name} (backup: {backup.name})")
    print("Legacy expectations updated for actual Snort platform support.")


if __name__ == "__main__":
    main()
