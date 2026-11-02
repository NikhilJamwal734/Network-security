from pathlib import Path
import importlib.util
import pytest

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("json_colour_installer", BASE / "scripts" / "install_json_colour.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@pytest.fixture
def project(tmp_path: Path):
    for rel in mod.TARGETS:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes((BASE / "tests" / "fixtures" / rel.name).read_bytes())
    api = tmp_path / "frontend/src/api/logs.ts"
    api.parent.mkdir(parents=True, exist_ok=True)
    api.write_text("// existing typed log API", encoding="utf8")
    # Files outside the two UI targets must never be changed.
    other = tmp_path / "app/core/audit_logging.py"
    other.parent.mkdir(parents=True)
    other.write_text("# old backend untouched", encoding="utf8")
    log = tmp_path / "logs/security_analysis.log"
    log.parent.mkdir()
    log.write_text('{"event":"analysis_completed","filename":"x.cfg"}\n', encoding="utf8")
    return tmp_path


def test_install_changes_only_two_pages_and_rollback(project):
    originals = {rel: (project / rel).read_bytes() for rel in mod.TARGETS}
    assert len(mod.install(project)) == 2
    assert (project / "app/core/audit_logging.py").read_text() == "# old backend untouched"
    assert (project / "logs/security_analysis.log").read_text() == '{"event":"analysis_completed","filename":"x.cfg"}\n'
    tsx = (project / mod.TARGETS[0]).read_text()
    assert "JsonLogLine" in tsx and "fa-logs-summary" not in tsx and "fa-log-row" not in tsx
    assert 'JSON.stringify(value)' in tsx
    assert len(mod.install(project)) == 0  # repeat does not rewrite
    assert len(mod.rollback(project)) == 2
    for rel, original in originals.items():
        assert (project / rel).read_bytes() == original


def test_unknown_custom_frontend_not_overwritten(project):
    target = project / mod.TARGETS[0]
    target.write_bytes(target.read_bytes() + b"// custom edit\n")
    with pytest.raises(ValueError, match="customized"):
        mod.install(project)
    assert not (project / mod.MANIFEST).exists()
    assert not (project / mod.BACKUP_DIR).exists()


def test_windows_bom_crlf_supported(project):
    for rel in mod.TARGETS:
        target = project / rel
        target.write_bytes(b"\xef\xbb\xbf" + target.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    mod.install(project)
    for rel in mod.TARGETS:
        raw = (project / rel).read_bytes()
        assert raw.startswith(b"\xef\xbb\xbf")
        assert b"\r\n" in raw and b"\r\r\n" not in raw
    mod.rollback(project)


def test_malformed_endings_rejected(project):
    target = project / mod.TARGETS[0]
    target.write_bytes(target.read_bytes().replace(b"\n", b"\r\r\n"))
    with pytest.raises(ValueError, match="line endings"):
        mod.install(project)


def test_edit_after_install_blocks_rollback(project):
    mod.install(project)
    target = project / mod.TARGETS[1]
    target.write_bytes(target.read_bytes() + b"/* edited */")
    with pytest.raises(ValueError, match="Edited since upgrade"):
        mod.rollback(project)


def test_no_api_dependency_fails_without_edit(project):
    (project / "frontend/src/api/logs.ts").unlink()
    with pytest.raises(ValueError, match="earlier Logs viewer"):
        mod.install(project)
    assert (project / mod.TARGETS[0]).read_bytes() == (BASE / "tests/fixtures/Logs.tsx").read_bytes()
