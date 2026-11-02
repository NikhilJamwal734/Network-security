from __future__ import annotations
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts'
sys.path.insert(0,str(SCRIPT))


def load(path, name):
    spec=spec_from_file_location(name,path)
    mod=module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod

backend=load(SCRIPT/'install_api_011_6.py','installer_116_backend')
frontend=load(ROOT/'frontend_patch/scripts/install_api_011_6_frontend.py','installer_116_frontend')
combined=load(SCRIPT/'install_all_api_011_6.py','installer_116_combined')
rollback_mod=load(SCRIPT/'rollback_api_011_6.py','installer_116_rollback')


def test_installs_idempotently_without_changing_dashboard(project):
    dashboard=project/'frontend/src/pages/UniversalAnalysis.tsx'
    dashboard.parent.mkdir(parents=True,exist_ok=True)
    dashboard.write_text('const dashboard = "all previous cards preserved";',encoding='utf-8')
    before=dashboard.read_bytes()
    changes=combined.install(project)
    assert sorted(changes)==sorted([
        'app/api/main.py', 'app/api/hardened_analysis.py', 'app/core/input_hardening.py',
        'frontend/src/api/universal.ts', 'frontend/src/utils/normalizedPdf.ts'])
    assert dashboard.read_bytes()==before
    assert combined.install(project)==[]
    api=(project/'frontend/src/api/universal.ts').read_text('utf-8')
    pdf=(project/'frontend/src/utils/normalizedPdf.ts').read_text('utf-8')
    assert api.count('/api/v1/analyze/hardened')==1
    assert api.count('input_security_review?: InputSecurityReview')==1
    assert pdf.count('Upload input validation — Detailed evidence')==1
    assert 'PDF EXPORT VALIDATION' not in pdf


def test_rejects_unknown_layout_before_writes(project):
    path=project/'frontend/src/api/universal.ts'
    path.write_text('changed file with no anchor',encoding='utf-8')
    with pytest.raises(ValueError):
        combined.install(project)
    assert not (project/'app/api/hardened_analysis.py').exists()
    assert not (project/'.api0116_install_manifest.json').exists()


def test_rollback_restores_exact_original_bytes(project):
    old={rel:(project/rel).read_bytes() for rel in [
        'app/api/main.py', 'frontend/src/api/universal.ts', 'frontend/src/utils/normalizedPdf.ts']}
    combined.install(project)
    paths=rollback_mod.rollback(project)
    assert len(paths)==5
    assert not (project/'.api0116_install_manifest.json').exists()
    for rel,original in old.items():
        assert (project/rel).read_bytes()==original
    assert not (project/'app/core/input_hardening.py').exists()
    assert not (project/'app/api/hardened_analysis.py').exists()


def test_rollback_refuses_unrelated_later_edit(project):
    combined.install(project)
    dst=project/'frontend/src/api/universal.ts'
    dst.write_bytes(dst.read_bytes()+b'\n// later edit\n')
    with pytest.raises(ValueError,match='changed since installation'):
        rollback_mod.rollback(project)
    assert (project/'app/api/hardened_analysis.py').exists()


def test_windows_crlf_utf8_bom_preserved(project):
    for rel in ('app/api/main.py','frontend/src/api/universal.ts','frontend/src/utils/normalizedPdf.ts'):
        path=project/rel
        old=path.read_bytes()
        path.write_bytes(b'\xef\xbb\xbf'+old.replace(b'\n',b'\r\n'))
    combined.install(project)
    for rel in ('app/api/main.py','frontend/src/api/universal.ts','frontend/src/utils/normalizedPdf.ts'):
        data=(project/rel).read_bytes()
        assert data.startswith(b'\xef\xbb\xbf')
        assert b'\r\n' in data
        assert data.count(b'\r\n')==data.count(b'\n')
    rollback_mod.rollback(project)


def test_invalid_utf8_fails_before_write(project):
    (project/'frontend/src/api/universal.ts').write_bytes(b'\x97')
    with pytest.raises(UnicodeDecodeError):
        combined.install(project)
    assert not (project/'.api0116_install_manifest.json').exists()


def test_does_not_override_customized_module(project):
    customized=project/'app/core/input_hardening.py'
    customized.write_bytes(b'# protected custom module\n')
    with pytest.raises(ValueError,match='Refusing to overwrite'):
        combined.install(project)
    assert customized.read_bytes()==b'# protected custom module\n'


def test_manifest_prevents_partial_reinstall(project):
    combined.install(project)
    path=project/'app/api/main.py'
    path.write_bytes(path.read_bytes()+b'\n# edited\n')
    with pytest.raises(ValueError,match='manifest exists'):
        combined.install(project)
