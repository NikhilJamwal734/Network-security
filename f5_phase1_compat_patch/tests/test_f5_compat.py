"""Run after installation: python -m pytest -q phase1_f5_patch/tests."""
import importlib.util
from pathlib import Path

import pytest
from app.f5_phase1_addon.parser import ParseError, parse, tokenize
from app.f5_phase1_addon.checks import analyze

BUNDLE = Path(__file__).resolve().parents[1]
SCRIPT = BUNDLE / 'scripts' / 'install_f5_compat.py'
spec = importlib.util.spec_from_file_location('f5_installer_under_test', SCRIPT)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


SAMPLE = (BUNDLE / 'examples' / 'f5_phase1_sample.conf').read_text(encoding='utf-8')


def test_four_checks_with_evidence_and_profile_attachment():
    result = analyze(parse(SAMPLE))
    assert {f['code'] for f in result['findings']} == {'F5-001', 'F5-003', 'F5-007'}
    assert {f['code'] for f in result['review_observations']} == {'F5-002'}
    assert result['summary']['total_findings'] == 3
    assert result['summary']['total_review_observations'] == 1
    for item in result['findings'] + result['review_observations']:
        assert item['line_number'] > 0
        assert item['associated_virtual_servers'] == ['/Common/example_virtual']


def test_inheritance_unknown_not_false_tls_findings():
    src = 'ltm profile client-ssl /Common/c {\n defaults-from /Common/clientssl\n}\n'
    result = analyze(parse(src))
    assert result['findings'] == []


def test_default_cipher_group_not_a_default_cipher_warning():
    src = 'ltm profile server-ssl /Common/s {\n ciphers DEFAULT\n cipher-group /Common/secure-ciphers\n peer-cert-mode require\n ca-file /Common/ca.crt\n}\n'
    result = analyze(parse(src))
    assert result['review_observations'] == []
    assert result['findings'] == []


def test_review_if_cert_inheritance_not_proven():
    src = 'ltm profile server-ssl /Common/s { defaults-from /Common/serverssl }'
    result = analyze(parse(src))
    assert len(result['review_observations']) == 1
    assert result['review_observations'][0]['confidence'] == 'insufficient_evidence'


def test_hsts_enabled_is_not_flagged():
    src = 'ltm profile http /Common/h { hsts { mode enabled } }'
    assert analyze(parse(src))['findings'] == []


def test_comments_quotes_nested_blocks_do_not_trigger_false_matches():
    src = '''# ltm profile client-ssl /Common/fake { options { no-tlsv1.3 } }
ltm profile client-ssl /Common/good {
    description "contains { braces } and no-tlsv1.3"
    options { no-sslv3 }
}
ltm rule /Common/example { when HTTP_REQUEST { if { 1 } { log local0. \"hello\" } } }
'''
    objects = parse(src)
    assert len(objects) == 1
    assert analyze(objects)['findings'] == []


def test_malformed_f5_braces_rejected():
    with pytest.raises(ParseError):
        parse('ltm profile http /Common/h { hsts { mode disabled }')


def test_log_secrets_not_in_result():
    src = SAMPLE + '\nltm profile server-ssl /Common/secret { passphrase SuperSecretPassword! ciphers MODERN peer-cert-mode require ca-file /Common/ca }'
    assert 'SuperSecretPassword!' not in str(analyze(parse(src)))


def test_installer_preserves_crlf_bom_and_rollback(tmp_path):
    root = tmp_path
    (root/'app/api').mkdir(parents=True)
    (root/'app/core').mkdir(parents=True)
    (root/'app/core/input_hardening.py').write_text('# existing\n')
    original = ('from fastapi import FastAPI\n'
                'from app.api.release_status import router as release_status_router\n'
                'app = FastAPI()\n'
                'app.include_router(release_status_router)\n')
    main_path = root/'app/api/main.py'
    original_bytes = b'\xef\xbb\xbf' + original.replace('\n', '\r\n').encode()
    main_path.write_bytes(original_bytes)
    changes = installer.install(root)
    assert len(changes) == 6
    assert main_path.read_bytes().startswith(b'\xef\xbb\xbf')
    assert b'\r\napp.include_router(f5_phase1_addon_router)\r\n' in main_path.read_bytes()
    assert installer.install(root) == []
    undone = installer.rollback(root)
    assert len(undone) == 6
    assert main_path.read_bytes() == original_bytes
    assert not (root/'app/f5_phase1_addon/api.py').exists()


def test_no_existing_custom_app_files_overwritten(tmp_path):
    (tmp_path/'app/api').mkdir(parents=True)
    (tmp_path/'app/core').mkdir(parents=True)
    (tmp_path/'app/core/input_hardening.py').write_text('# existing')
    (tmp_path/'app/api/main.py').write_text(
        'from app.api.release_status import router as release_status_router\n'
        'app.include_router(release_status_router)\n')
    (tmp_path/'app/api/f5_analysis.py').write_text('# custom')
    before = (tmp_path/'app/api/main.py').read_bytes()
    # Existing application modules are untouched by the namespaced addon.
    installer.install(tmp_path)
    assert (tmp_path/'app/api/f5_analysis.py').read_text() == '# custom'
    installer.rollback(tmp_path)
    assert (tmp_path/'app/api/main.py').read_bytes() == before


def test_installer_refuses_unsupported_main_layout(tmp_path):
    (tmp_path/'app/api').mkdir(parents=True)
    (tmp_path/'app/core').mkdir(parents=True)
    (tmp_path/'app/core/input_hardening.py').write_text('# existing')
    (tmp_path/'app/api/main.py').write_text('app = object()\n')
    with pytest.raises(ValueError, match='anchor'):
        installer.install(tmp_path)
    assert not (tmp_path/'app/f5_phase1_addon/api.py').exists()


def test_canonical_profile_resolution_avoids_unqualified_cross_partition():
    src = '''ltm profile http /Other/h { hsts { mode disabled } }
ltm virtual /Common/v { profiles { h {} } }
'''
    item = analyze(parse(src))['findings'][0]
    assert item['associated_virtual_servers'] == []


def test_quoted_nonascii_and_multiline_lines():
    src = 'ltm profile http /Common/ht {\n description "café"\n hsts {\n mode disabled\n }\n}'
    result = analyze(parse(src))
    assert result['findings'][0]['line_number'] == 4



def test_f5_api_accepts_sample_and_rejects_binary():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.f5_phase1_addon.api import router
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        response = client.post('/api/v1/analyze/f5/phase1',
                               files={'file': ('sample.conf', SAMPLE.encode('utf-8'), 'text/plain')})
        assert response.status_code == 200
        data = response.json()
        assert data['platform']['platform_id'] == 'f5_bigip'
        assert data['summary']['total_findings'] == 3
        assert data['input_security_review']['summary']['byte_count'] == len(SAMPLE.encode('utf-8'))
        rejected = client.post('/api/v1/analyze/f5/phase1',
                               files={'file': ('bad.conf', b'PK\x03\x04this is an archive', 'text/plain')})
        assert rejected.status_code == 422
        assert rejected.json()['detail']['code'] == 'binary_input'


def test_unqualified_profile_reference_uses_virtual_partition():
    src = "ltm profile http /Other/h { hsts { mode disabled } }\nltm virtual /Other/v { profiles { h {} } }"
    result = analyze(parse(src))
    assert result['findings'][0]['associated_virtual_servers'] == ['/Other/v']


def test_preexisting_custom_parser_survives_install_and_rollback(tmp_path):
    (tmp_path/'app/api').mkdir(parents=True)
    (tmp_path/'app/core').mkdir(parents=True)
    (tmp_path/'app/parsers').mkdir(parents=True)
    original = b'# Existing user implementation of the F5 parser\r\n'
    (tmp_path/'app/parsers/f5_bigip_parser.py').write_bytes(original)
    (tmp_path/'app/core/input_hardening.py').write_text('# existing')
    main = tmp_path/'app/api/main.py'
    existing = ('from app.api.release_status import router as release_status_router\n'
                'app.include_router(release_status_router)\n')
    main.write_text(existing)
    dry = installer.install(tmp_path, dry_run=True)
    assert 'app/f5_phase1_addon/parser.py' in dry
    assert (tmp_path/'app/parsers/f5_bigip_parser.py').read_bytes() == original
    installer.install(tmp_path)
    assert (tmp_path/'app/parsers/f5_bigip_parser.py').read_bytes() == original
    installer.rollback(tmp_path)
    assert (tmp_path/'app/parsers/f5_bigip_parser.py').read_bytes() == original
    assert main.read_text() == existing


def test_avoid_duplicate_original_phase1_api(tmp_path):
    (tmp_path/'app/api').mkdir(parents=True)
    (tmp_path/'app/core').mkdir(parents=True)
    (tmp_path/'app/core/input_hardening.py').write_text('# existing')
    main = tmp_path/'app/api/main.py'
    original = ('from app.api.release_status import router as release_status_router\n'
                'from app.api.f5_analysis import router as f5_phase1_router\n'
                'app.include_router(release_status_router)\n'
                'app.include_router(f5_phase1_router)\n')
    main.write_text(original)
    with pytest.raises(ValueError, match='Original F5 Phase 1 API'):
        installer.install(tmp_path, dry_run=True)
    assert main.read_text() == original
    assert not (tmp_path/'app/f5_phase1_addon').exists()
