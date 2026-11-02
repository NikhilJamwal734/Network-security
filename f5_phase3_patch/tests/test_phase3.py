from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('f5_phase3_installer', ROOT / 'scripts/install_f5_phase3.py')
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)
FIX = ROOT / 'tests/fixtures'

@pytest.fixture
def project(tmp_path):
    for rel in (MOD.API, MOD.PHASE2):
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text('phase2 preexisting module\n', encoding='utf-8')
    for src, dest in (('UniversalAnalysis.tsx', MOD.PAGE), ('f5Phase1.ts', MOD.ADAPTER)):
        f = tmp_path / dest
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes((FIX/src).read_bytes())
    return tmp_path


def test_install_and_idempotent(project):
    before={rel:(project/rel).read_bytes() for rel in MOD.FILES}
    assert set(MOD.install(project, dry_run=True)) == set(MOD.FILES)
    assert {rel:(project/rel).read_bytes() for rel in MOD.FILES} == before
    assert len(MOD.install(project)) == 2
    assert MOD.install(project) == []
    api=(project/MOD.ADAPTER).read_text(encoding='utf-8')
    page=(project/MOD.PAGE).read_text(encoding='utf-8')
    assert 'form.append("evidence_json"' in api
    assert 'F5_EVIDENCE_MAX_BYTES = 16_384' in api
    assert 'f5EvidenceFile' in page
    assert 'Choose optional F5 operator evidence JSON' in page
    assert MOD.rollback(project) == list(MOD.FILES)
    assert {rel:(project/rel).read_bytes() for rel in MOD.FILES} == before


def test_crlf_bom(project):
    for rel in MOD.FILES:
        f=project/rel
        f.write_bytes(b'\xef\xbb\xbf'+f.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
    originals={rel:(project/rel).read_bytes() for rel in MOD.FILES}
    assert len(MOD.install(project)) == 2
    for rel in MOD.FILES:
        assert (project/rel).read_bytes().startswith(b'\xef\xbb\xbf')
        assert b'\r\r\n' not in (project/rel).read_bytes()
    MOD.rollback(project)
    assert {rel:(project/rel).read_bytes() for rel in MOD.FILES} == originals


def test_fail_closed_missing_phase2(project):
    (project/MOD.PHASE2).unlink()
    with pytest.raises(ValueError,match='Phases 1 and 2'):
        MOD.install(project)
    assert not (project/MOD.MANIFEST).exists()


def test_modified_frontend_is_not_overwritten(project):
    file=project/MOD.PAGE
    file.write_text(file.read_text('utf8').replace('const [file, setFile]', 'const [chosen, setFile]'), encoding='utf8')
    with pytest.raises(ValueError, match='customized|Unexpected'):
        MOD.install(project)
    assert not (project/MOD.MANIFEST).exists()


def test_partial_phase3_refused(project):
    file=project/MOD.ADAPTER
    file.write_text(MOD.patch_adapter(file.read_text('utf8')),encoding='utf8')
    with pytest.raises(ValueError,match='Partial Phase 3'):
        MOD.install(project)
    assert not (project/MOD.MANIFEST).exists()


def test_rollback_refuses_later_changes(project):
    MOD.install(project)
    file=project/MOD.ADAPTER
    file.write_bytes(file.read_bytes()+b'// changed\n')
    with pytest.raises(ValueError,match='Modified'):
        MOD.rollback(project)
    assert (project/MOD.MANIFEST).is_file()


def test_symlink_fail_closed(project):
    target=project/MOD.PAGE
    target.unlink()
    try:
        target.symlink_to(FIX/'UniversalAnalysis.tsx')
    except OSError:
        pytest.skip('OS does not permit creating symlink')
    with pytest.raises(ValueError,match='Symlinks'):
        MOD.install(project)


def test_legacy_routes_remain_unchanged(project):
    original={rel:(project/rel).read_bytes() for rel in (MOD.API,MOD.PHASE2)}
    MOD.install(project)
    assert {rel:(project/rel).read_bytes() for rel in (MOD.API,MOD.PHASE2)} == original


def test_backend_evidence_schema_and_rejection():
    # Exercise the original Phase 2 backend evidence parser from the bundled fixture.
    import ast
    import re
    from datetime import date
    src=(FIX/'backend_evidence_validator.py').read_text(encoding='utf-8')
    tree=ast.parse(src)
    include={'MAX_EVIDENCE_BYTES','MAX_BACKUPS','SAFE_NAME','ALLOWED_STATUS'}
    nodes=[]
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t,ast.Name) and t.id in include for t in node.targets):
            nodes.append(node)
        elif isinstance(node, ast.ClassDef) and node.name=='EvidenceError':
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name=='parse_evidence':
            nodes.append(node)
    module=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)]+nodes,type_ignores=[])
    ns={'re':re,'json':json,'date':date}
    exec(compile(ast.fix_missing_locations(module),'<backend-schema>','exec'),ns)
    valid=(ROOT/'examples/f5_phase3_evidence.json').read_text('utf8')
    result=ns['parse_evidence'](valid)
    assert len(result['ucs_backups'])==2
    for bad in ['{"password":"never"}', '{"ucs_backups":[{"name":"../private.ucs","encrypted":false}]}',
                '{"signature_updates":{"status":"bogus","last_installed":null}}', '{"ucs_backups":{}}']:
        with pytest.raises(ns['EvidenceError']):
            ns['parse_evidence'](bad)


def test_typescript_source_parse(project):
    if not shutil.which('tsc'):
        pytest.skip('tsc not installed')
    MOD.install(project)
    (project/'frontend/src/api/universal.ts').write_bytes((FIX/'universal.ts').read_bytes())
    (project/'frontend/src/vite-env.d.ts').write_text('interface ImportMetaEnv { readonly DEV: boolean; readonly VITE_API_BASE_URL?: string; }\ninterface ImportMeta { readonly env: ImportMetaEnv; }\n', encoding='utf8')
    cmd=['tsc','--noEmit','--skipLibCheck','--moduleResolution','bundler','--module','esnext','--target','es2022','--lib','es2022,dom',
        str(project/MOD.ADAPTER),str(project/'frontend/src/vite-env.d.ts')]
    proc=subprocess.run(cmd,capture_output=True,text=True,timeout=40)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_examples_valid():
    sample=json.loads((ROOT/'examples/f5_phase3_evidence.json').read_text(encoding='utf8'))
    assert isinstance(sample['ucs_backups'],list) and sample['signature_updates']['status']=='failed'


def test_smoke_validator_positive_and_negative():
    import importlib.util
    script=ROOT/'tools/verify_phase3_api.py'
    sp=importlib.util.spec_from_file_location('f5_phase3_smoke', script)
    module=importlib.util.module_from_spec(sp)
    sp.loader.exec_module(module)
    baseline={'platform':{'platform_id':'f5_bigip'},'summary':{'total_findings':3,'total_review_observations':2},
        'findings':[{'code':x} for x in ('F5-001','F5-003','F5-007')],
        'review_observations':[{'code':'F5-005','confidence':'not_assessed'},{'code':'F5-006','confidence':'not_assessed'}]}
    supplied={'platform':{'platform_id':'f5_bigip'},'summary':{'total_findings':4,'total_review_observations':1},
        'findings':[{'code':x} for x in ('F5-001','F5-003','F5-007','F5-005')],
        'review_observations':[{'code':'F5-006','confidence':'operator_supplied_unverified'}],
        'f5_phase2_review':{'operator_evidence_supplied':True}}
    assert not module.verify(baseline,supplied)
    bad=dict(supplied)
    bad['summary']={'total_findings':10,'total_review_observations':1}
    assert module.verify(baseline,bad)
    assert module.main  # script entrypoint available


def test_react_source_syntax_via_typescript(project):
    if not shutil.which('node') or not shutil.which('tsc'):
        pytest.skip('Node/TypeScript not installed')
    MOD.install(project)
    file=project/MOD.PAGE
    # Request TS diagnostics for parsing, not full project type checking.
    npm = shutil.which('npm.cmd') or shutil.which('npm')
    if npm is None:
        pytest.skip('npm not installed')
    roots = subprocess.run([npm, 'root', '-g'], capture_output=True, text=True, timeout=10)
    candidates = [Path(roots.stdout.strip())/'typescript'] if roots.returncode == 0 else []
    candidates += [Path.cwd()/'frontend/node_modules/typescript', ROOT/'frontend/node_modules/typescript']
    ts_module = next((candidate for candidate in candidates if candidate.exists()), None)
    if ts_module is None:
        pytest.skip('TypeScript library not available for TSX parser check')
    proc=subprocess.run(['node','-e', '''const ts=require(process.argv[1]);const fs=require('fs');
      const src=fs.readFileSync(process.argv[2],'utf8');
      const f=ts.createSourceFile('UniversalAnalysis.tsx',src,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
      if(f.parseDiagnostics.length){console.error(f.parseDiagnostics.map(d=>d.messageText).join('\\n'));process.exit(1)}''',
        str(ts_module),str(file)],capture_output=True,text=True,timeout=20)
    assert proc.returncode == 0, proc.stderr
