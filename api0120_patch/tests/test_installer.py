from pathlib import Path
import json
import pytest

from install_all_api_012_0 import (install, plan, text_update, MANIFEST)
from rollback_api_012_0 import rollback


def test_install_and_second_install_noop(project):
    old_dashboard=(project/'frontend/src/pages/UniversalAnalysis.tsx').read_bytes()
    changed=install(project)
    assert sorted(changed)==['app/api/main.py','app/api/release_status.py']
    assert (project/'frontend/src/pages/UniversalAnalysis.tsx').read_bytes()==old_dashboard
    assert install(project)==[]
    s=(project/'app/api/main.py').read_text('utf8')
    assert s.count('app.include_router(release_status_router)')==1
    assert s.count('from app.api.release_status import router as release_status_router')==1


def test_rollback_restore_exact_bytes(project):
    old=(project/'app/api/main.py').read_bytes()
    install(project)
    assert sorted(rollback(project))==['app/api/main.py','app/api/release_status.py']
    assert (project/'app/api/main.py').read_bytes()==old
    assert not (project/'app/api/release_status.py').exists()
    assert not (project/MANIFEST).exists()


def test_rollback_refuses_edit_without_partially_reverting(project):
    install(project)
    before=(project/'app/api/main.py').read_bytes()
    (project/'app/api/release_status.py').write_bytes(b'# changed\n')
    with pytest.raises(ValueError,match='changed'):
        rollback(project)
    assert (project/'app/api/main.py').read_bytes()==before
    assert (project/MANIFEST).exists()


def test_manifest_prevents_reinstall_after_changes(project):
    install(project)
    p=project/'app/api/main.py'
    p.write_bytes(p.read_bytes()+b'\n# local edit\n')
    with pytest.raises(ValueError,match='changed'):
        install(project)


def test_unknown_routers_fail_before_writing(project):
    (project/'app/api/main.py').write_text('no anchors here',encoding='utf8')
    with pytest.raises(ValueError,match='anchors'):
        install(project)
    assert not (project/'app/api/release_status.py').exists()


def test_missing_prereq_fails_before_writing(project):
    (project/'app/core/input_hardening.py').unlink()
    with pytest.raises(ValueError,match='prerequisite'):
        install(project)
    assert not (project/MANIFEST).exists()


def test_bom_and_crlf_preserved(project):
    p=project/'app/api/main.py'
    original=p.read_bytes()
    p.write_bytes(b'\xef\xbb\xbf'+original.replace(b'\n',b'\r\n'))
    install(project)
    assert p.read_bytes().startswith(b'\xef\xbb\xbf')
    assert b'\r\n' in p.read_bytes()
    assert p.read_bytes().count(b'\r\n')==p.read_bytes().count(b'\n')
    rollback(project)
    assert p.read_bytes()==b'\xef\xbb\xbf'+original.replace(b'\n',b'\r\n')


def test_bad_utf8_fails_safely(project):
    (project/'app/api/main.py').write_bytes(b'\x97')
    with pytest.raises(UnicodeDecodeError):
        install(project)
    assert not (project/MANIFEST).exists()


def test_partial_registration_refused(project):
    path=project/'app/api/main.py'
    path.write_bytes(path.read_bytes()+b'from app.api.release_status import router as release_status_router\n')
    with pytest.raises(ValueError,match='Partial'):
        plan(project)


def test_custom_release_module_preserved(project):
    dest=project/'app/api/release_status.py'
    dest.write_text('# user version',encoding='utf8')
    with pytest.raises(ValueError,match='Refusing to overwrite'):
        install(project)
    assert dest.read_text('utf8')=='# user version'


def test_duplicate_anchor_rejected(project):
    path=project/'app/api/main.py'
    path.write_bytes(path.read_bytes()+b'app.include_router(hardened_analysis_router)\n')
    with pytest.raises(ValueError,match='anchors'):
        install(project)


def test_existing_temp_file_prevents_install(project):
    (project/'app/api/main.py.api0120.tmp').write_bytes(b'temp')
    with pytest.raises(ValueError,match='backup/temp'):
        install(project)
    assert not (project/MANIFEST).exists()


def test_manifest_corruption_is_rejected(project):
    install(project)
    (project/MANIFEST).write_text('{',encoding='utf8')
    with pytest.raises(json.JSONDecodeError):
        install(project)
