from __future__ import annotations
import ast
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'install_report_corrections.py'
spec = importlib.util.spec_from_file_location('f5_reporting_fix_installer', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def project(tmp_path, crlf=False, bom=False):
    """Reconstruct the pre-fix sources from original Phase1+2 kit fixtures."""
    package = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures'
    repo = tmp_path / 'project'
    source = {
        mod.PDF: (package / 'normalizedPdf.full.ts').read_text(encoding='utf-8'),
        mod.ADAPTER: (package / 'f5Phase1.phase2.ts').read_text(encoding='utf-8'),
        mod.REVIEW: (package / 'review.phase2.py').read_text(encoding='utf-8'),
    }
    for name, data in source.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(mod.encode(data, '\r\n' if crlf else '\n', bom))
    return repo


def test_install_and_idempotence(tmp_path):
    root = project(tmp_path)
    old = {key: (root/key).read_bytes() for key in mod.FILES}
    assert set(mod.plan(root)) == set(mod.FILES)
    assert len(mod.install(root, dry_run=True)) == 3
    assert not (root/mod.MANIFEST).exists()
    assert len(mod.install(root)) == 3
    assert mod.install(root) == []
    pdf = (root/mod.PDF).read_text(encoding='utf-8')
    ui = (root/mod.ADAPTER).read_text(encoding='utf-8')
    assert 'dedicated F5 upload endpoint' in pdf
    assert 'F5 Phase 2 - virtual logging association and iRule inventory subset' in ui
    assert 'ASM::disable can suppress ASM/Advanced WAF inspection' in pdf
    assert 'inputSecurity.sha256' in pdf
    assert len(mod.rollback(root)) == 3
    for key in mod.FILES:
        assert (root/key).read_bytes() == old[key]


@pytest.mark.parametrize('eol,bom',[(False,False),(True,False),(True,True)])
def test_preserves_encoding_and_rolls_back(tmp_path,eol,bom):
    root = project(tmp_path,eol,bom)
    old = {key:(root/key).read_bytes() for key in mod.FILES}
    mod.install(root)
    for key in mod.FILES:
        raw = (root/key).read_bytes()
        assert raw.startswith(b'\xef\xbb\xbf') == bom
        if eol:
            assert b'\r\n' in raw and b'\r\r\n' not in raw
        else:
            assert b'\r' not in raw
    mod.rollback(root)
    assert all((root/key).read_bytes()==value for key,value in old.items())


def test_other_vendors_keep_original_provenance(tmp_path):
    root=project(tmp_path)
    mod.install(root)
    pdf=(root/mod.PDF).read_text(encoding='utf-8')
    assert pdf.count('Validation occurred before analysis at the API-011.6 endpoint.') == 1
    assert 'report.platform.platform_id === "f5_bigip"' in pdf
    assert '? inputSecurity.limitations' not in pdf  # Ternary is rendered in a separate expression
    assert ': inputSecurity.limitations' in pdf


def test_phase2_operator_supplied_evidence_vs_not_assessed(tmp_path):
    root=project(tmp_path)
    mod.install(root)
    adapter=(root/mod.ADAPTER).read_text(encoding='utf-8')
    assert 'hasUcsEvidence ? "assessed" : "not_assessed"' in adapter
    assert 'hasSignatureEvidence ? "assessed" : "not_assessed"' in adapter
    assert 'signature_update_evidence_supplied' in adapter
    backend=(root/mod.REVIEW).read_text(encoding='utf-8')
    ast.parse(backend)
    assert "'ucs_evidence_supplied': 'ucs_backups' in evidence" in backend
    assert "'signature_update_evidence_supplied': 'signature_updates' in evidence" in backend


def test_irule_context_does_not_dump_arbitrary_text(tmp_path):
    root=project(tmp_path)
    mod.install(root)
    source=(root/mod.REVIEW).read_text(encoding='utf-8')
    # Check source-level construction of the context note without importing real app.
    assert "re.fullmatch(r'/[A-Za-z0-9/_-]{1,40}', literal)" in source
    assert "source line {calls[0].line}" in source
    assert 'exec(' not in source


def test_existing_custom_file_fails_before_writing(tmp_path):
    root=project(tmp_path)
    pdf=root/mod.PDF
    original=pdf.read_text(encoding='utf-8')
    pdf.write_text(original.replace('section("F5 BIG-IP Phases 1 + 2 - Detailed technical evidence")', 'section("Custom")'),encoding='utf-8')
    originals={key:(root/key).read_bytes() for key in mod.FILES}
    with pytest.raises(ValueError,match='F5 Phase 2 PDF evidence'):
        mod.install(root)
    assert {key:(root/key).read_bytes() for key in mod.FILES}==originals
    assert not (root/mod.MANIFEST).exists()


def test_partial_patch_fails_closed(tmp_path):
    root=project(tmp_path)
    target=root/mod.ADAPTER
    txt=target.read_text(encoding='utf-8')
    target.write_text(txt.replace('  const limitations = body.coverage.limitations.filter', '  const limitations = foo.filter'),encoding='utf-8')
    with pytest.raises(ValueError, match='F5 Phase 2 evidence flags'):
        mod.install(root)
    assert not (root/mod.MANIFEST).exists()


def test_rollback_rejects_subsequent_changes(tmp_path):
    root=project(tmp_path)
    mod.install(root)
    target=root/mod.PDF
    target.write_bytes(target.read_bytes()+b'\n// customized\n')
    with pytest.raises(ValueError,match='File changed after patch'):
        mod.rollback(root)
    assert (root/mod.MANIFEST).exists()


def test_rejects_symlink_target(tmp_path):
    root=project(tmp_path)
    existing=root/mod.PDF
    existing.unlink()
    outside=tmp_path/'outside.ts'
    outside.write_text('malicious',encoding='utf-8')
    try:
        existing.symlink_to(outside)
    except (OSError,NotImplementedError):
        pytest.skip('Symlinks not available')
    with pytest.raises(ValueError,match='Symlink'):
        mod.plan(root)


def _load_irule_description(tmp_path):
    """Exercise the new safe evidence formatter in isolation from the app runtime."""
    import re
    from dataclasses import dataclass
    root=project(tmp_path)
    mod.install(root)
    module=ast.parse((root/mod.REVIEW).read_text(encoding='utf-8'))
    function=next(node for node in module.body if isinstance(node,ast.FunctionDef) and node.name=='_irule_description')
    fn=ast.Module(body=[function],type_ignores=[])
    ast.fix_missing_locations(fn)
    @dataclass
    class Token:
        value:str
        line:int
    @dataclass
    class ConfigObject:
        body:tuple[Token,...]
    ns={'re':re, 'ConfigObject':ConfigObject}
    exec(compile(fn,'irule_helper','exec'),ns)
    return ns['_irule_description'],Token,ConfigObject


def test_irule_sample_context_and_source_line(tmp_path):
    fn,Token,ConfigObject = _load_irule_description(tmp_path)
    obj=ConfigObject(tuple(Token(x,i) for i,x in enumerate([
        'when','HTTP_REQUEST','{','if','{','[HTTP::uri]','contains','/test',
        '}','{','ASM::disable','}','}'
    ],start=11)))
    actual=fn(obj,['ASM::disable'])
    assert 'source line 21' in actual
    assert 'HTTP_REQUEST event block' in actual
    assert 'contains "/test"' in actual
    assert 'no runtime vulnerability' in actual


def test_irule_context_does_not_include_unapproved_strings(tmp_path):
    fn,Token,ConfigObject=_load_irule_description(tmp_path)
    obj=ConfigObject(tuple(Token(x,10) for x in [
        'when','HTTP_REQUEST','if','[HTTP::uri]','contains',
        '/secret?token=PRIVATE','ASM::disable']))
    actual=fn(obj,['ASM::disable'])
    assert 'PRIVATE' not in actual and '/secret?' not in actual
    assert 'ASM::disable' in actual
