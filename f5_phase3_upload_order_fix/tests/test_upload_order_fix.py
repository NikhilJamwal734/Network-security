import importlib.util
import json
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sp=importlib.util.spec_from_file_location('fix',ROOT/'scripts/install_upload_order_fix.py')
mod=importlib.util.module_from_spec(sp)
sp.loader.exec_module(mod)
FIXTURE=ROOT/'tests/fixtures/UniversalAnalysis.phase3.tsx'

@pytest.fixture
def project(tmp_path):
    f=tmp_path/mod.TARGET
    f.parent.mkdir(parents=True,exist_ok=True)
    f.write_bytes(FIXTURE.read_bytes())
    return tmp_path

def test_install_order_and_rollback(project):
    file=project/mod.TARGET
    original=file.read_bytes()
    assert mod.install(project,dry_run=True)==[mod.TARGET]
    assert file.read_bytes()==original
    assert mod.install(project)==[mod.TARGET]
    assert mod.install(project)==[]
    txt=file.read_text('utf8')
    assert txt.count(mod.NEW)==1
    assert 'setF5EvidenceFile(null); // Evidence is F5-specific.' in txt
    # The installed frontend retains evidence on first config selection only;
    # changing an existing config still clears stale evidence.
    assert 'file ? null : previous' in txt
    assert mod.rollback(project)==[mod.TARGET]
    assert file.read_bytes()==original

def test_crlf_and_bom(project):
    file=project/mod.TARGET
    file.write_bytes(b'\xef\xbb\xbf'+file.read_bytes().replace(b'\n',b'\r\n'))
    old=file.read_bytes()
    mod.install(project)
    assert file.read_bytes().startswith(b'\xef\xbb\xbf')
    assert b'\r\r\n' not in file.read_bytes()
    assert b'\r\n' in file.read_bytes()
    mod.rollback(project)
    assert old==file.read_bytes()

def test_changed_file_rejected(project):
    file=project/mod.TARGET
    file.write_text(file.read_text('utf8').replace(mod.OLD,'setF5EvidenceFile(null); // user edit'),encoding='utf8')
    before=file.read_bytes()
    with pytest.raises(ValueError,match='not found exactly once'):
        mod.install(project)
    assert file.read_bytes()==before
    assert not (project/mod.MANIFEST).exists()

def test_rollback_rejects_modification(project):
    mod.install(project)
    file=project/mod.TARGET
    file.write_bytes(file.read_bytes()+b'//other changes')
    with pytest.raises(ValueError,match='Files changed'):
        mod.rollback(project)

def test_idempotent_prepatched_source(project):
    file=project/mod.TARGET
    file.write_bytes(mod.transform(file.read_bytes()))
    assert mod.install(project)==[]

def test_path_symlink_refused(project):
    f=project/mod.TARGET
    f.unlink()
    try:
        f.symlink_to(FIXTURE)
    except OSError:
        pytest.skip('OS symlink permissions')
    with pytest.raises(ValueError,match='Symlink'):
        mod.install(project)
