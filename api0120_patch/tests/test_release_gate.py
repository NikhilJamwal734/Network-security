from pathlib import Path
import json
import pytest
from install_all_api_012_0 import install
from release_gate import audit, structural_checks, validate_loopback, pdf_check, main


def test_gate_incomplete_without_tests_build_pdf_and_smoke(project):
    install(project)
    r=audit(project)
    assert r['release']=='12.0'
    assert r['local_gate']=='incomplete'
    assert r['production_ready'] is False
    assert r['counts']['not_run']==4
    assert r['counts']['deployment_warnings']>=2


def test_checks_detect_missing_hardened_router(project):
    install(project)
    p=project/'app/api/main.py'
    p.write_bytes(p.read_bytes().replace(b'app.include_router(hardened_analysis_router)',b'# removed router'))
    r=audit(project)
    assert r['local_gate']=='failed'
    assert any(e['name']=='release router registration' and e['status']=='fail' for e in r['checks'])


def test_checks_find_bad_frontend_endpoint(project):
    install(project)
    p=project/'frontend/src/api/universal.ts'
    p.write_text('const url = "/api/v1/analyze/pipeline-validation";',encoding='utf8')
    r=audit(project)
    assert r['local_gate']=='failed'


def test_local_only_smoke_url(project):
    for u in ('https://example.com','http://192.168.1.1:8000','http://user:pass@127.0.0.1:8000','http://localhost:8000/path'):
        with pytest.raises(ValueError):
            validate_loopback(u)
    validate_loopback('http://localhost:8000')
    validate_loopback('http://127.0.0.1:8000')


def test_missing_pdf_fails_gracefully(project):
    install(project)
    entry=pdf_check(project/'nothing.pdf')
    assert entry['status']=='fail'
    assert 'PDF' in entry['name']


def test_missing_smoke_file_fails_gracefully(project):
    install(project)
    result=audit(project,smoke_file=project/'missing.conf')
    assert result['local_gate']=='failed'
    assert any(x['name']=='localhost upload smoke' and x['status']=='fail' for x in result['checks'])


def test_gate_json_no_pii_no_user_configuration(project,tmp_path):
    install(project)
    out=tmp_path/'gate.json'
    code=main(['--root',str(project),'--json-out',str(out)])
    assert code==2
    data=json.loads(out.read_text(encoding='utf8'))
    assert data['production_ready'] is False
    assert data['local_gate']=='incomplete'
    assert 'C:\\' not in out.read_text(encoding='utf8')


def test_local_gate_status_not_confused_with_production_ready(project,monkeypatch):
    install(project)
    from release_gate import audit
    monkeypatch.setattr('release_gate.execute',lambda *a,**kw:{'name':a[0],'status':'pass','summary':'ok','category':'local','recommendation':''})
    monkeypatch.setattr('release_gate.pdf_check',lambda *a:{'name':'pdf','status':'pass','summary':'ok','category':'local','recommendation':''})
    sm=project/'sample.conf';sm.write_text('x',encoding='utf8')
    scr=project/'api0116_patch/scripts/smoke_test_api_011_6.py';scr.parent.mkdir(parents=True);scr.write_text('# test',encoding='utf8')
    monkeypatch.setattr('release_gate.shutil.which',lambda *a:'npm')
    result=audit(project,run_tests=True,run_frontend_build=True,pdf=sm,smoke_file=sm)
    assert result['local_gate']=='passed'
    assert result['production_ready'] is False
