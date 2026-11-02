"""Update only legacy assertions that predate *registered* Suricata support.

Run from project root after installing API-009.5:
    .\\.venv-win\\Scripts\\python.exe scripts\\update_api_009_5_legacy_tests.py

Requires the verified API-009.4 test migration to have run first. All expected
text is verified before any edits; backups saved as .api0095.bak.
"""

from pathlib import Path

TESTS = Path(__file__).resolve().parents[1] / "tests"
UPDATES = [
    ("test_api_009_1_architecture.py",
     "def test_default_registry_contains_verified_cisco_asa_and_snort():",
     "def test_default_registry_contains_verified_cisco_asa_snort_and_suricata():"),
    ("test_api_009_1_architecture.py",
     '    assert len(entries) == 2\n    assert entries[0].platform_id == "cisco_asa"\n'
     '    assert entries[1].platform_id == "snort"\n    assert entries[1].family is DeviceFamily.IDS',
     '    assert len(entries) == 3\n    assert entries[0].platform_id == "cisco_asa"\n'
     '    assert entries[1].platform_id == "snort"\n    assert entries[1].family is DeviceFamily.IDS\n'
     '    assert entries[2].platform_id == "suricata"\n    assert entries[2].family is DeviceFamily.IDS'),
    ("test_api_009_1_architecture.py",
     '@pytest.mark.parametrize("unknown", ["zeek", "suricata", "palo_alto", "../../etc", ""])',
     '@pytest.mark.parametrize("unknown", ["zeek", "osquery", "palo_alto", "../../etc", ""])'),
    ("test_api_009_2_detection.py",
     '    assert set(entries) == {"cisco_asa", "snort"}',
     '    assert set(entries) == {"cisco_asa", "snort", "suricata"}'),
    ("test_api_009_2_detection.py",
     '    assert ".rules" in entries["snort"]["extensions"]',
     '    assert ".rules" in entries["snort"]["extensions"]\n'
     '    assert entries["suricata"]["family"] == "ids"\n'
     '    assert ".yaml" in entries["suricata"]["extensions"]'),
    ("test_api_009_2_detection.py",
     '@pytest.mark.parametrize("requested", ["zeek", "suricata", "../../tmp", "", "palo_alto"])',
     '@pytest.mark.parametrize("requested", ["zeek", "osquery", "../../tmp", "", "palo_alto"])'),
    ("test_api_009_2_detection.py",
     'def test_ids_yaml_not_misclassified():\n'
     '    assert detect_platform(["rule-files:", " - local.rules"], REGISTRY).status is DetectionStatus.UNSUPPORTED',
     'def test_ids_yaml_detects_registered_suricata():\n'
     '    result = detect_platform(["rule-files:", " - local.rules"], REGISTRY)\n'
     '    assert result.status is DetectionStatus.SUPPORTED\n'
     '    assert result.platform_id == "suricata"'),
    ("test_api_009_2_detection.py",
     'def test_api_explicit_unsupported_platform_rejected():\n'
     '    response = upload(ASA_CONFIG, platform="suricata")',
     'def test_api_explicit_unsupported_platform_rejected():\n'
     '    response = upload(ASA_CONFIG, platform="osquery")'),
    ("test_api_009_3_normalized.py",
     'def test_normalized_unsupported_platform_is_rejected():\n'
     '    response = post("/api/v1/analyze/normalized", params={"platform": "suricata"})',
     'def test_normalized_unsupported_platform_is_rejected():\n'
     '    response = post("/api/v1/analyze/normalized", params={"platform": "osquery"})'),
    ("test_api_009_4_snort.py",
     'def test_suricata_yaml_not_automatically_marked_snort():\n'
     '    result = detect_platform(["rule-files:", " - local.rules"], REGISTRY)\n'
     '    assert result.status is DetectionStatus.UNSUPPORTED',
     'def test_suricata_yaml_is_not_misclassified_as_snort():\n'
     '    result = detect_platform(["rule-files:", " - local.rules"], REGISTRY)\n'
     '    assert result.status is DetectionStatus.SUPPORTED\n'
     '    assert result.platform_id == "suricata"'),
    ("test_api_009_4_snort.py",
     '    assert {p["platform_id"] for p in response.json()["platforms"]} == {"cisco_asa", "snort"}',
     '    assert {p["platform_id"] for p in response.json()["platforms"]} == '
     '{"cisco_asa", "snort", "suricata"}'),
]


def main() -> None:
    final: dict[Path, str] = {}
    for name, old, new in UPDATES:
        path = TESTS / name
        if path not in final:
            final[path] = path.read_text(encoding="utf-8")
        text = final[path]
        if new in text:
            continue  # Safe to rerun (new text may contain old as a prefix).
        if text.count(old) != 1:
            raise RuntimeError(
                f"Unexpected test contents: {name}. "
                "No files were changed. Confirm API-009.4 migrations were applied."
            )
        final[path] = text.replace(old, new, 1)
    pending = []
    for path, new_text in final.items():
        old_text = path.read_text(encoding="utf-8")
        if old_text == new_text:
            print("Already current:", path.name)
            continue
        backup = path.with_suffix(path.suffix + ".api0095.bak")
        if backup.exists():
            raise RuntimeError(f"Backup already exists; refusing overwrite: {backup}")
        pending.append((path, old_text, new_text, backup))
    for path, old_text, new_text, backup in pending:
        backup.write_text(old_text, encoding="utf-8")
        path.write_text(new_text, encoding="utf-8")
        print(f"Updated: {path.name} (backup: {backup.name})")
    print("API-009.5 legacy expectations aligned with registered Suricata support.")


if __name__ == "__main__":
    main()
