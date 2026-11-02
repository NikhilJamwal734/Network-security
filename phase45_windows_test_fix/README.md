# Windows unit-test fixture correction for Recommendations 1–3

## Diagnosis

1. `ModuleNotFoundError: No module named 'app.f5_phase5_addon'`: the application files are placed at `app/f5_phase5_addon/` by the **installer**. Extracting the prior ZIP only creates `phase4_5_bundle/app/...`. Run the guarded installer after checking `--dry-run`; then rerun the tests.
2. `test_preserve_crlf` incorrectly uses `p.read_bytes().replace(b'\n', b'\r\n')`. `Path.write_text()` translates LF to CRLF on Windows, so that replacement can turn `CRLF` into `CRCRLF`. This trips the production installer's intentionally strict line-ending validator. The fix changes **only that test line** to normalize CRLF to LF first and then build CRLF.
3. A `[FAIL] EXE integrity ...` line inside the **deliberate negative test** is expected when that test finishes `ok`; do not confuse it with the real EXE acceptance result.
4. The Starlette deprecation warning is not the cause of either error.

## Apply safely (PowerShell, from project root)

```powershell
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-Phase45-Windows-Test-Fix.zip" -DestinationPath . -Force
.\.venv-win\Scripts\python.exe .\phase45_windows_test_fix\scripts\apply.py . --dry-run
.\.venv-win\Scripts\python.exe .\phase45_windows_test_fix\scripts\apply.py .
.\.venv-win\Scripts\python.exe .\phase4_5_bundle\scripts\install.py . --dry-run
.\.venv-win\Scripts\python.exe .\phase4_5_bundle\scripts\install.py .
.\.venv-win\Scripts\python.exe -m unittest discover -s .\phase4_5_bundle\tests -p 'test_*.py' -v
```

If you previously installed Recommendations 1–3, the installer should report `INSTALL PASS: 0 source files`; the test repair is still safe.

Confirm newly created module with:

```powershell
Test-Path .\app\f5_phase5_addon\assurance.py
.\.venv-win\Scripts\python.exe -c "from app.f5_phase5_addon.assurance import build_assurance; print('F5 assurance import: PASS')"
```

Rollback **test-only change**, leaving installed app source intact:

```powershell
.\.venv-win\Scripts\python.exe .\phase45_windows_test_fix\scripts\apply.py . --rollback
```

For complete application rollback, use the **original** `phase4_5_bundle/scripts/install.py --rollback` only after checking its source-manifest conditions.

Do not confuse test success with full regression, fresh packaged EXE acceptance or independently verified live F5 posture.
