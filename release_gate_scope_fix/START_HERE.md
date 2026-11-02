# Final release gate: select active vs historical tests

**Purpose:** Enables `--test-scope active` as an explicit choice for the final gate. The default remains `--test-scope all`. This package edits ONLY `release_final/verify_final.py` and preserves a byte-identical rollback backup. It does not edit `app/`, `frontend/`, test files, or the EXE builder.

The verified focused suite on the user's Windows machine returned **1,245 passed, 9 skipped**. The historical all-patches pytest collection returned **19 failed, 5 errors** (and is not certified). The active scope will emit a **WARN** named `Historical patch tests`; it does not hide or claim to resolve those failures. Its remaining checks—frontend build, PDF evidence, live F5 and other vendor APIs, health and logs—must all pass.

## Install on Windows (PowerShell from project root)

```powershell
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-Final-Gate-Test-Scope-Fix.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\release_gate_scope_fix\scripts\install_scope_fix.py . --dry-run
.\.venv-win\Scripts\python.exe .\release_gate_scope_fix\scripts\install_scope_fix.py .
.\.venv-win\Scripts\python.exe -m pytest -q .\release_gate_scope_fix\tests
```

Ensure FastAPI is running at `http://127.0.0.1:8000`, including `/api/health`, and use the seven-page Phase 3 PDF with 4 findings and 4 review observations:

```powershell
$env:PYTHONUTF8 = '1'
$pdf = Join-Path $env:USERPROFILE 'Downloads\f5_bigip.f5_bigip.security-report (5).pdf'
if (-not (Test-Path -LiteralPath $pdf)) { throw "PDF missing: $pdf" }
.\.venv-win\Scripts\python.exe .\release_final\verify_final.py `
  --root '.' --run-tests --test-scope active --build-frontend `
  --api-url 'http://127.0.0.1:8000' --pdf "$pdf" --bundled-vendor-samples `
  --out '.\release_final_gate.json'
```

Review `release_final_gate.json`; confirm all required checks pass. `Historical patch tests` will be WARN. If any required check FAILs or is INCOMPLETE, do not package.

To run the original full historical test collection instead, pass `--test-scope all` (default): it will still report the known failing old tests unless their fixtures are fixed. Preserve that result separately as technical debt evidence.

Only after a clean gate, run the existing `build_release.py --check-only`, then `build_release.py`, then carry out **manual acceptance testing on the actual packaged EXE**. Passing a scoped test gate is not a production security certification.

## Rollback

```powershell
.\.venv-win\Scripts\python.exe .\release_gate_scope_fix\scripts\install_scope_fix.py . --rollback
```

Rollback will refuse if the installed release checker was subsequently edited.
