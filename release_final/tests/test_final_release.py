from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import verify_final as v
import build_release as b


def test_safe_url_loopback():
    assert v.safe_url('http://localhost:8000') == 'http://localhost:8000'
    for bad in ('https://localhost:8000','http://127.0.0.1', 'http://8.8.8.8:8000',
                'http://localhost:8000/path','http://localhost:8000?x=1',
                'http://me:pw@localhost:8000', 'http://localhost:8000/#/foo'):
        with pytest.raises(ValueError):
            v.safe_url(bad)


def test_multipart_contains_fields_without_contents_in_path():
    body, content_type = v.multipart('synthetic.conf',b'hostname ASA\n',b'{"status":"failed"}')
    assert 'multipart/form-data; boundary=' in content_type
    assert body.count(b'name="file"') == 1
    assert body.count(b'name="evidence_json"') == 1
    assert b'hostname ASA' in body
    assert body.endswith(b'--\r\n')


def test_source_fingerprint_and_change(tmp_path):
    p=tmp_path/'app/api/main.py'
    p.parent.mkdir(parents=True)
    p.write_text('initial',encoding='utf8')
    a=v.source_fingerprint(tmp_path)
    assert a['app/api/main.py']==hashlib.sha256(b'initial').hexdigest()
    p.write_text('modified')
    assert v.source_fingerprint(tmp_path) != a


def test_gate_default_incomplete(tmp_path):
    a=SimpleNamespace(run_tests=False,build_frontend=False,pdf=None,api_url=None,bundled_vendor_samples=False,
          **{x+'_file':None for x in v.VENDORS})
    result=v.make_report(tmp_path,a)
    assert result['gate']=='FAIL'  # missing root application files
    assert result['production_certified'] is False
    assert any(c['status']=='INCOMPLETE' for c in result['checks'])


def test_consistent_f5_and_vendor():
    payload={'platform':{'platform_id':'f5_bigip'},'summary':{'total_findings':0,'total_review_observations':0},
             'findings':[],'review_observations':[],'input_security_review':{'status':'accepted'}}
    assert v.is_consistent(payload,True)
    payload['summary']['total_review_observations']=1
    assert not v.is_consistent(payload,True)
    payload['summary']['total_review_observations']=0
    payload['platform']['platform_id']='snort'
    assert v.is_consistent(payload,False)
    payload['input_security_review']['status']='rejected'
    assert not v.is_consistent(payload,False)


def test_f5_api_happy_and_bad_metadata(tmp_path, monkeypatch):
    cf=tmp_path/'f5_phase2_patch/examples/f5_phase2_sample.conf'
    ev=tmp_path/'f5_phase3_patch/examples/f5_phase3_evidence.json'
    cf.parent.mkdir(parents=True);ev.parent.mkdir(parents=True)
    cf.write_bytes(b'f5 test\n');ev.write_bytes(b'{"ucs_backups":[]}')
    def payload(with_meta):
        findings=[{'code':c} for c in ('F5-001','F5-003','F5-007')]
        review=[{'code':'F5-005','confidence':'not_assessed'}, {'code':'F5-006','confidence':'not_assessed'}, {'code':'F5-002'}, {'code':'F5-004'}, {'code':'F5-008'}]
        if with_meta:
            findings.append({'code':'F5-005','confidence':'operator_supplied_unverified'})
            review=[{'code':'F5-006','confidence':'operator_supplied_unverified'}, {'code':'F5-002'}, {'code':'F5-004'}, {'code':'F5-008'}]
        return {'platform':{'platform_id':'f5_bigip'},
           'summary':{'total_findings':len(findings),'total_review_observations':len(review)},
           'findings':findings,'review_observations':review,
           'f5_phase2_review':{'operator_evidence_supplied':with_meta},
           'input_security_review':{'status':'accepted','sha256':hashlib.sha256(cf.read_bytes()).hexdigest()}}
    def request(base,path,data,evidence=None,platform=None,filename='sample.conf'):
        return (422,{}) if evidence==b'{ broken JSON' or data.startswith(b'PK\x03\x04') else (200,payload(evidence is not None))
    monkeypatch.setattr(v,'request_json',request)
    assert v.live_f5(tmp_path,'http://localhost:8000')['status']=='PASS'


def test_f5_api_missing_operator_flag_fails(tmp_path,monkeypatch):
    cf=tmp_path/'f5_phase2_patch/examples/f5_phase2_sample.conf'
    ev=tmp_path/'f5_phase3_patch/examples/f5_phase3_evidence.json'
    cf.parent.mkdir(parents=True);ev.parent.mkdir(parents=True)
    cf.write_bytes(b'config');ev.write_bytes(b'{}')
    monkeypatch.setattr(v,'request_json',lambda *a, **kw:(200,{}))
    assert v.live_f5(tmp_path,'http://localhost:8000')['status']=='FAIL'


def test_non_f5_fixture_filename_respects_extension(monkeypatch,tmp_path):
    p=tmp_path/'suri.yaml';p.write_text('rule-files:\n  - local.rules\n')
    seen=[]
    def fake(base,path,config,evidence=None,platform=None,filename=''):
        seen.append((platform,filename))
        return 200, {'platform':{'platform_id':'suricata'},'summary':{'total_findings':0},
                     'findings':[],'input_security_review':{'status':'accepted'}}
    monkeypatch.setattr(v,'request_json',fake)
    result=v.live_vendor('http://127.0.0.1:8000','suricata',p)
    assert result['status']=='PASS' and seen==[('suricata','synthetic.yaml')]


def test_pdf_check_incomplete(tmp_path):
    assert v.pdf_check(None)['status']=='INCOMPLETE'
    path=tmp_path/'broken.pdf';path.write_bytes(b'%PDF-xxxx')
    assert v.pdf_check(path)['status']=='FAIL'


def test_existing_f5_pdf_if_available():
    pdf=Path('/mnt/data/f5_bigip.f5_bigip.security-report (5).pdf')
    if pdf.is_file():
        assert v.pdf_check(pdf)['status']=='PASS'


def test_gate_check_refuses_fail_and_modification(tmp_path):
    p=tmp_path/'app/api/main.py';p.parent.mkdir(parents=True);p.write_text('x')
    fp=v.source_fingerprint(tmp_path)
    required = ['Python regression suite','React production build','F5 evidence PDF','Health API',
                'JSON Logs API','F5 live API','cisco_asa API','fortios API','snort API','suricata API']
    data={'release':'FirewallAnalyzer-final-F5-Phase3','gate':'PASS',
          'counts':{'failed':0,'incomplete':0},
          'checks':[{'status':'PASS','name':name} for name in required],
          'source_sha256':fp}
    manifest=tmp_path/'status.json';manifest.write_text(json.dumps(data))
    assert b.check_gate(tmp_path,manifest)['gate']=='PASS'
    p.write_text('y')
    with pytest.raises(ValueError, match='changed'):
        b.check_gate(tmp_path,manifest)
    data['gate']='INCOMPLETE';manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='PASS'):
        b.check_gate(tmp_path,manifest)


def test_windows_npm_builder_detection(tmp_path):
    path=tmp_path/'builder.py'
    path.write_text('commands = [["npm", "run", "build"]]')
    assert b.detect_bad_npm_runner(path)
    path.write_text('commands = [["npm.cmd", "run", "build"]]')
    assert not b.detect_bad_npm_runner(path)


def test_readonly_fixture_samples_nonempty():
    examples=ROOT/'examples'
    for name in ('cisco_asa.conf','fortios.conf','snort.conf','suricata.yaml'):
        assert (examples/name).is_file() and 0<(examples/name).stat().st_size<4096


def test_no_live_network_by_default(tmp_path, monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError('No HTTP requests permitted')
    monkeypatch.setattr(v,'request_json',forbidden)
    a=SimpleNamespace(run_tests=False,build_frontend=False,pdf=None,api_url=None,bundled_vendor_samples=False,
          **{x+'_file':None for x in v.VENDORS})
    assert v.make_report(tmp_path,a)['gate']=='FAIL'


def test_live_core_apis(monkeypatch):
    def service(base,path):
        if path == '/api/health':
            return 200, {'status':'ok'}
        if path == '/api/v1/logs?stream=application&limit=1':
            return 200, {'stream':'application', 'entries': []}
        raise AssertionError('Unexpected route')
    monkeypatch.setattr(v,'get_json',service)
    results=v.live_core_services('http://127.0.0.1:8000')
    assert all(item['status']=='PASS' for item in results)


def test_live_logs_failure_blocks(monkeypatch):
    def service(base,path):
        return (404,{}) if 'logs' in path else (200,{'status':'ok'})
    monkeypatch.setattr(v,'get_json',service)
    results=v.live_core_services('http://127.0.0.1:8000')
    assert [item['status'] for item in results] == ['PASS','FAIL']


def test_source_fingerprint_includes_additional_source_files(tmp_path):
    p=tmp_path/'app/api/extra.py';p.parent.mkdir(parents=True);p.write_text('a')
    q=tmp_path/'frontend/src/pages/NewPanel.tsx';q.parent.mkdir(parents=True);q.write_text('b')
    r=v.source_fingerprint(tmp_path)
    assert 'app/api/extra.py' in r
    assert 'frontend/src/pages/NewPanel.tsx' in r
    q.write_text('changed')
    assert v.source_fingerprint(tmp_path) != r


def test_gate_refuses_omitted_critical_test(tmp_path):
    required = ['Python regression suite','React production build','F5 evidence PDF','Health API',
                'JSON Logs API','F5 live API','cisco_asa API','fortios API','snort API']
    p=tmp_path/'app/api/main.py';p.parent.mkdir(parents=True);p.write_text('present')
    data={'release':'FirewallAnalyzer-final-F5-Phase3','gate':'PASS',
          'counts':{'failed':0,'incomplete':0},
          'checks':[{'name':x,'status':'PASS'} for x in required],
          'source_sha256':v.source_fingerprint(tmp_path)}
    f=tmp_path/'gate.json';f.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='Missing required PASS checks'):
        b.check_gate(tmp_path,f)
