import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import zipfile
import pytest

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('scope_installer',BASE/'scripts'/'install_scope_fix.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
BUNDLE = Path(__file__).resolve().parent / 'verify_final_original.py'

@pytest.fixture
def project(tmp_path):
    target = tmp_path/'release_final'/'verify_final.py'
    target.parent.mkdir()
    target.write_bytes(BUNDLE.read_bytes())
    (tmp_path/'release_gate_scope_fix').mkdir()
    return tmp_path

def test_dry_run_non_mutating(project):
    before=(project/'release_final/verify_final.py').read_bytes()
    assert 'DRY RUN PASS' in mod.install(project,True,False)
    assert (project/'release_final/verify_final.py').read_bytes()==before
    assert not (project/'release_gate_scope_fix/scope_fix_manifest.json').exists()

def test_install_and_repeat_and_rollback(project):
    old=(project/'release_final/verify_final.py').read_bytes()
    assert 'INSTALLED' in mod.install(project,False,False)
    new=(project/'release_final/verify_final.py').read_bytes()
    assert new!=old and b'--test-scope' in new
    assert 'ALREADY INSTALLED' in mod.install(project,False,False)
    assert (project/'release_final/verify_final.py').read_bytes()==new
    assert 'ROLLED BACK' in mod.install(project,False,True)
    assert (project/'release_final/verify_final.py').read_bytes()==old

def test_modified_after_install_refuses_rollback(project):
    mod.install(project,False,False)
    target=project/'release_final/verify_final.py'
    target.write_bytes(target.read_bytes()+b'\n# modified\n')
    with pytest.raises(ValueError,match='changed'):
        mod.install(project,False,True)

def test_crlf_bom_preserved(project):
    target=project/'release_final/verify_final.py'
    data=target.read_bytes().replace(b'\n',b'\r\n')
    target.write_bytes(b'\xef\xbb\xbf'+data)
    old=target.read_bytes()
    mod.install(project,False,False)
    new=target.read_bytes()
    assert new.startswith(b'\xef\xbb\xbf')
    assert b'\r\n' in new and b'\n' not in new.replace(b'\r\n',b'')
    mod.install(project,False,True)
    assert target.read_bytes()==old

def test_unsupported_version_fails_closed(project):
    target=project/'release_final/verify_final.py'
    target.write_text('print(1)',encoding='utf8')
    with pytest.raises(ValueError,match='Unsupported'):
        mod.install(project,False,False)
    assert target.read_text(encoding='utf8')=='print(1)'

def test_missing_active_targets_fails_closed(project):
    mod.install(project,False,False)
    source=(project/'release_final/verify_final.py')
    spec=importlib.util.spec_from_file_location('release_check_tmp',source)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    # no live checks needed: confirms active suite refuses missing directories
    m.preflight=lambda _: []
    m.source_fingerprint=lambda _: {}
    m.pdf_check=lambda _:m.item('F5 evidence PDF','INCOMPLETE','missing')
    m.VENDORS=()
    a=SimpleNamespace(run_tests=True,test_scope='active',build_frontend=False,pdf=None,api_url=None,bundled_vendor_samples=False)
    r=m.make_report(project,a)
    test=next(x for x in r['checks'] if x['name']=='Python regression suite')
    assert test['status']=='FAIL'
    assert any(x['name']=='Historical patch tests' and x['status']=='WARN' for x in r['checks'])
