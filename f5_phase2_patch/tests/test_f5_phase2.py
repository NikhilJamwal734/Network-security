"""Phase 2 acceptance tests. Run from project root after installation."""
from __future__ import annotations
import importlib.util
import json
import shutil
from pathlib import Path

import pytest
from app.f5_phase1_addon.parser import parse
from app.f5_phase1_addon.checks import analyze
from app.f5_phase2_addon.review import extend_report, parse_evidence, EvidenceError

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / 'examples' / 'f5_phase2_sample.conf').read_text(encoding='utf-8')
EVIDENCE = (ROOT / 'examples' / 'f5_phase2_evidence.json').read_text(encoding='utf-8')
SCRIPT = ROOT / 'scripts' / 'install_f5_phase2.py'
spec = importlib.util.spec_from_file_location('phase2_installer', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def review(source=SAMPLE, evidence=None):
    objs = parse(source)
    return extend_report(analyze(objs), objs, source, evidence)


def test_phase1_findings_unchanged_and_all_phase2_codes_present():
    out = review()
    assert {'F5-001', 'F5-003', 'F5-007'}.issubset({f['code'] for f in out['findings']})
    assert {'F5-002', 'F5-004', 'F5-005', 'F5-006', 'F5-008'}.issubset({x['code'] for x in out['review_observations']})
    assert out['summary']['total_findings'] == len(out['findings'])
    assert out['summary']['total_review_observations'] == len(out['review_observations'])
    assert out['summary']['total_irules'] == 1
    assert out['schema_version'] == 'f5-phase2-1.0'


def test_operator_supplied_evidence_is_explicit_and_bounded():
    out = review(evidence=EVIDENCE)
    items = [x for x in out['findings'] if x['code'] == 'F5-005']
    assert len(items) == 1
    assert items[0]['confidence'] == 'operator_supplied_unverified'
    assert items[0]['evidence']['observed'] == 'false (operator assertion)'
    assert any(x['code'] == 'F5-006' for x in out['review_observations'])
    assert not any(x['code'] == 'F5-005' for x in out['review_observations'])


def test_phase2_does_not_execute_irule_or_leak_raw_contents():
    src = SAMPLE + '\nltm rule /Common/private { when HTTP_REQUEST { set password "SUPER-SECRET-FOO-BAR" } }\n'
    data = review(src)
    assert 'SUPER-SECRET-FOO-BAR' not in json.dumps(data)
    assert data['summary']['total_irules'] == 2


def test_disabled_virtual_does_not_generate_logging_warning():
    src = 'ltm virtual /Common/disabled_vs {\n disabled\n security-log-profiles { none }\n}\n'
    out = review(src)
    assert not any(item['code'] == 'F5-004' for item in out['review_observations'])


def test_logging_profile_attached_avoids_false_warning():
    src = 'ltm virtual /Common/good {\n security-log-profiles { /Common/waf-log }\n}\n'
    assert not any(x['code'] == 'F5-004' for x in review(src)['review_observations'])


def test_non_f5_text_is_not_an_irule():
    src = '''# ltm rule /Common/commented { when HTTP_REQUEST { ASM::disable } }
ltm profile http /Common/h { hsts { mode enabled } }
'''
    assert review(src)['summary']['total_irules'] == 0


@pytest.mark.parametrize('payload', [
    '{bad', '[]', '{}junk', json.dumps({'password': 'not_allowed'}),
    json.dumps({'ucs_backups': [{'name': '../secret.ucs', 'encrypted': False}]}),
    json.dumps({'ucs_backups': [{'name': 'safe.ucs', 'encrypted': 'false'}]}),
    json.dumps({'signature_updates': {'status': [], 'last_installed': None}}),
    json.dumps({'signature_updates': {'status': 'current', 'last_installed': '2026-99-88'}}),
    'x' * 17000,
])
def test_malformed_evidence_fails_closed(payload):
    with pytest.raises(EvidenceError):
        parse_evidence(payload)


def test_absent_evidence_is_not_scored():
    data=review()
    assert data['summary']['security_score'] is None
    assert not any(x['code'] in {'F5-005', 'F5-006'} for x in data['findings'])


def temp_project(tmp_path, bom=False, crlf=False):
    root = tmp_path / 'project'
    def put(rel, data):
        target = root/rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if crlf:
            data=data.replace('\n','\r\n')
        target.write_bytes((b'\xef\xbb\xbf' if bom else b'') + data.encode('utf-8'))
    fixtures=Path(__file__).parent/'fixtures'
    original_api=(fixtures/'api.phase1.py').read_text(encoding='utf-8')
    frontend=(fixtures/'f5Phase1.ts').read_text(encoding='utf-8')
    pdf=(fixtures/'normalizedPdf.ts').read_text(encoding='utf-8')
    put(mod.API, original_api)
    put(mod.UI, frontend)
    put(mod.PDF, pdf)
    return root


@pytest.mark.parametrize('crlf,bom', [(False,False),(True,True)])
def test_installer_idempotent_and_rollback(tmp_path, crlf, bom):
    root=temp_project(tmp_path,bom,crlf)
    api_before=(root/mod.API).read_bytes()
    ui_before=(root/mod.UI).read_bytes()
    pdf_before=(root/mod.PDF).read_bytes()
    planned=mod.install(root, dry_run=True)
    assert len(planned)==5
    assert not (root/mod.MANIFEST).exists()
    assert len(mod.install(root))==5
    assert mod.install(root)==[]
    assert b'extend_report' in (root/mod.API).read_bytes()
    assert b'F5 BIG-IP Phases 1 + 2' in (root/mod.PDF).read_bytes()
    assert len(mod.rollback(root))==5
    assert (root/mod.API).read_bytes()==api_before
    assert (root/mod.UI).read_bytes()==ui_before
    assert (root/mod.PDF).read_bytes()==pdf_before
    assert not (root/mod.NEW_FILES[0]).exists()


def test_installer_fails_before_modifications_on_unknown_api(tmp_path):
    root=temp_project(tmp_path)
    api=root/mod.API
    api.write_text(api.read_text(encoding='utf-8').replace('report = analyze(objects)', 'result = analyze(objects)'),encoding='utf-8')
    before=api.read_bytes()
    with pytest.raises(ValueError):
        mod.install(root)
    assert api.read_bytes()==before
    assert not (root/mod.MANIFEST).exists()


def test_rollback_refuses_modified_file(tmp_path):
    root=temp_project(tmp_path)
    mod.install(root)
    target=root/mod.API
    target.write_bytes(target.read_bytes()+b'\n# changed\n')
    with pytest.raises(ValueError):
        mod.rollback(root)
    assert (root/mod.MANIFEST).exists()


def test_fastapi_endpoint_with_and_without_operator_evidence():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.f5_phase1_addon.api import router
    api = FastAPI()
    api.include_router(router)
    with TestClient(api) as client:
        ordinary = client.post('/api/v1/analyze/f5/phase1', files={'file': ('f5.conf', SAMPLE.encode(), 'text/plain')})
        assert ordinary.status_code == 200, ordinary.text
        report = ordinary.json()
        assert 'F5-004' in {x['code'] for x in report['review_observations']}
        assert report['summary']['total_findings'] == len(report['findings'])
        with_evidence = client.post('/api/v1/analyze/f5/phase1',
            files={'file': ('f5.conf', SAMPLE.encode(), 'text/plain')},
            data={'evidence_json': EVIDENCE})
        assert with_evidence.status_code == 200, with_evidence.text
        assert 'F5-005' in {x['code'] for x in with_evidence.json()['findings']}
        malformed = client.post('/api/v1/analyze/f5/phase1',
            files={'file': ('f5.conf', SAMPLE.encode(), 'text/plain')},
            data={'evidence_json': '{bad'})
        assert malformed.status_code == 422
        assert malformed.json()['detail']['code'] == 'invalid_f5_evidence'
