from __future__ import annotations
import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('security_check_module', ROOT / 'app/core/input_hardening.py')
mod = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def test_good_utf8_config_and_bom_are_accepted_without_exposing_content():
    content = b'\xef\xbb\xbfaccess-list ACL extended permit tcp any any eq 443\r\n'
    out = mod.inspect_config_bytes(content, filename='fw.cfg', platform='cisco_asa')
    assert out['status'] == 'accepted'
    assert out['summary']['byte_count'] == len(content)
    assert out['summary']['line_count'] == 1
    assert out['summary']['checks_passed'] == 6
    assert len(out['sha256']) == 64
    assert b'access-list' not in repr(out).encode()


@pytest.mark.parametrize('content,code', [
    (b'', 'empty_upload'), (b'  \r\n', 'empty_upload'),
    (b'PK\x03\x04garbage', 'binary_input'), (b'%PDF-1.4\n', 'binary_input'),
    (b'MZ' + b'X' * 4, 'binary_input'), (b'\xff', 'invalid_encoding'),
    (b'a\x00b', 'unexpected_control'), (b'abc\x1b[1m', 'unexpected_control'),
    (b'\x00\x00\xfe\xff', 'binary_input'),
])
def test_rejects_binary_bad_encoding_empty(content, code):
    with pytest.raises(mod.InputProblem) as caught:
        mod.inspect_config_bytes(content, filename='firewall.yaml', platform=None)
    assert caught.value.code == code
    if content:
        assert content.decode('latin-1') not in str(caught.value)


@pytest.mark.parametrize('filename', ['../evil.cfg','..\\evil.cfg','C:\\temp\\x.cfg','a\x00.cfg',
                                        'report/one.yaml','.','..',' x.cfg','x.cfg ','x.cfg.',''])
def test_rejects_untrusted_filename(filename):
    with pytest.raises(mod.InputProblem) as caught:
        mod.inspect_config_bytes(b'config firewall\n', filename=filename, platform=None)
    assert caught.value.code == 'invalid_filename'


def test_rejects_unsupported_platform():
    with pytest.raises(mod.InputProblem) as caught:
        mod.inspect_config_bytes(b'a\n', filename='a.txt', platform='suricata; echo hello')
    assert caught.value.code == 'unsupported_platform'


def test_overlong_line_and_large_bytes_rejected():
    with pytest.raises(mod.InputProblem) as caught:
        mod.inspect_config_bytes(b'x' * (mod.MAX_LINE_LENGTH + 1), filename='a.txt', platform=None)
    assert caught.value.code == 'overlong_line'
    with pytest.raises(mod.InputProblem) as caught:
        mod.inspect_config_bytes(b'x' * (mod.MAX_CONFIG_BYTES + 1), filename='a.txt', platform=None)
    assert caught.value.status_code == 413


def test_max_lines_rejected_without_unbounded_output(monkeypatch):
    monkeypatch.setattr(mod, 'MAX_LINES', 2)
    with pytest.raises(mod.InputProblem) as caught:
        mod.inspect_config_bytes(b'a\nb\nc\n', filename='a.txt', platform=None)
    assert caught.value.code == 'too_many_lines'
