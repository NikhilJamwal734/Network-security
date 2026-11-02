r"""Migrate only outdated platform-count expectations after FortiOS registration.

Run from project root after installing API-009.6:
    .\.venv-win\Scripts\python.exe scripts\update_api_009_6_legacy_tests.py

Backups: *.py.api0096.bak. All replacements are verified before any write.
No test is deleted, skipped or globally relaxed.
"""

from pathlib import Path

TESTS = Path(__file__).resolve().parents[1] / "tests"
UPDATES: tuple[tuple[str, str, str], ...] = (
    (
        "test_api_009_1_architecture.py",
        "def test_default_registry_contains_verified_cisco_asa_snort_and_suricata():",
        "def test_default_registry_contains_four_verified_platforms():",
    ),
    (
        "test_api_009_1_architecture.py",
        '''    assert len(entries) == 3
    assert entries[0].platform_id == "cisco_asa"
    assert entries[1].platform_id == "snort"
    assert entries[1].family is DeviceFamily.IDS
    assert entries[2].platform_id == "suricata"
    assert entries[2].family is DeviceFamily.IDS''',
        '''    assert len(entries) == 4
    assert entries[0].platform_id == "cisco_asa"
    assert entries[1].platform_id == "fortios"
    assert entries[1].family is DeviceFamily.FIREWALL
    assert entries[2].platform_id == "snort"
    assert entries[2].family is DeviceFamily.IDS
    assert entries[3].platform_id == "suricata"
    assert entries[3].family is DeviceFamily.IDS''',
    ),
    (
        "test_api_009_2_detection.py",
        '    assert set(entries) == {"cisco_asa", "snort", "suricata"}',
        '    assert set(entries) == {"cisco_asa", "fortios", "snort", "suricata"}',
    ),
    (
        "test_api_009_2_detection.py",
        '    assert ".yaml" in entries["suricata"]["extensions"]',
        '    assert ".yaml" in entries["suricata"]["extensions"]\n'
        '    assert entries["fortios"]["family"] == "firewall"\n'
        '    assert ".conf" in entries["fortios"]["extensions"]',
    ),
    (
        "test_api_009_4_snort.py",
        '    assert {p["platform_id"] for p in response.json()["platforms"]} == {"cisco_asa", "snort", "suricata"}',
        '    assert {p["platform_id"] for p in response.json()["platforms"]} == {"cisco_asa", "fortios", "snort", "suricata"}',
    ),
    (
        "test_api_009_5_suricata.py",
        '    assert [d.platform_id for d in REGISTRY.list_platforms()] == ["cisco_asa", "snort", "suricata"]',
        '    assert [d.platform_id for d in REGISTRY.list_platforms()] == ["cisco_asa", "fortios", "snort", "suricata"]',
    ),
    (
        "test_api_009_5_suricata.py",
        '    assert {p["platform_id"] for p in response.json()["platforms"]} == {"cisco_asa", "snort", "suricata"}',
        '    assert {p["platform_id"] for p in response.json()["platforms"]} == {"cisco_asa", "fortios", "snort", "suricata"}',
    ),
)


def main() -> None:
    future: dict[Path, str] = {}
    for name, before, after in UPDATES:
        path = TESTS / name
        if path not in future:
            future[path] = path.read_text(encoding="utf-8")
        current = future[path]
        if after in current:
            continue
        if current.count(before) != 1:
            raise RuntimeError(
                f"Unexpected contents in {name}. No files were changed. "
                "Check that API-009.5 tests are installed and migrated."
            )
        future[path] = current.replace(before, after, 1)

    pending: list[tuple[Path, str, str, Path]] = []
    for path, updated in future.items():
        current = path.read_text(encoding="utf-8")
        if current == updated:
            print("Already current:", path.name)
            continue
        backup = path.with_suffix(path.suffix + ".api0096.bak")
        if backup.exists():
            raise RuntimeError(f"Backup exists; refusing overwrite: {backup}")
        pending.append((path, current, updated, backup))
    for path, old, new, backup in pending:
        backup.write_text(old, encoding="utf-8")
        path.write_text(new, encoding="utf-8")
        print(f"Updated: {path.name} (backup: {backup.name})")
    print("API-009.6: prior platform catalog assertions updated for FortiOS.")


if __name__ == "__main__":
    main()
