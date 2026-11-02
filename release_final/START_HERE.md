# FirewallAnalyzer — Final Integration & Regression Gate

**Release target:** F5 BIG-IP Phases 1–3 integrated with Cisco ASA, FortiOS, Snort, Suricata, local JSON Logs, detailed PDF, and Windows EXE.

This package is **a non-destructive test and release gate**, not a replacement analyzer, fix to an unknown local error, or prebuilt EXE. It does not modify app/frontend source files. It does run your project's test suite and Vite build, which may update standard generated test/build artifacts. It saves `release_final_gate.json` with check statuses and source hashes; raw configurations and log entries are not saved in it.

## Installation

1. Back up your existing project (or commit it to Git) before release work.
2. Extract this ZIP into the **project root** (the folder containing `app`, `frontend`, `desktop_packaging`, `.venv-win`). This adds only the `release_final` folder.
3. Start your local FastAPI service in a separate PowerShell terminal and leave it running:

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
.\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000
```

4. Save or locate the latest F5 PDF from the **F5 configuration + Phase 3 JSON evidence** test. It should contain 4 findings and 4 review observations. Use its actual Windows path in the next command.
5. In a second PowerShell terminal, in the project root, run:

```powershell
.\.venv-win\Scripts\python.exe .\release_final\verify_final.py `
  --root "." `
  --run-tests `
  --build-frontend `
  --api-url "http://127.0.0.1:8000" `
  --pdf "C:\path\to\f5_bigip.f5_bigip.security-report (5).pdf" `
  --bundled-vendor-samples `
  --out ".\release_final_gate.json"
```

**Or use the PowerShell wrapper** (replace the PDF path):

```powershell
.\release_final\Run-FinalRegression.ps1 -PdfPath "C:\path\to\f5_bigip.f5_bigip.security-report (5).pdf"
```

The checker verifies: required application files; F5 integration; source consistency; the full local Python test suite; React production build; F5 report evidence; live health and JSON Logs endpoints; F5 endpoint with/without JSON; malformed JSON rejection; binary upload rejection; and four vendor API smoke tests using synthetic fixtures. The exact ZIP bundles bundled fixtures are synthetic and **might be rejected by stricter parsers**. Replace them with small, known-good local test configs, never production secrets:

```powershell
.\.venv-win\Scripts\python.exe .\release_final\verify_final.py `
 --root "." --run-tests --build-frontend `
 --api-url "http://127.0.0.1:8000" `
 --pdf "C:\path\to\f5_bigip.f5_bigip.security-report (5).pdf" `
 --cisco-asa-file "C:\testdata\asa.conf" `
 --fortios-file "C:\testdata\forti.conf" `
 --snort-file "C:\testdata\snort.conf" `
 --suricata-file "C:\testdata\suricata.yaml" `
 --out ".\release_final_gate.json"
```

## How to interpret the gate

- **PASS** — all required automated checks passed on your current Windows project. Manual UI, packaged EXE and device security acceptance are **not** proven by this status.
- **FAIL** — a required test or source preflight failed. Do not package or ship; inspect the failed check.
- **INCOMPLETE** — one or more required checks were not run. Do not package or ship.

Exit codes: 0 PASS; 1 FAIL; 2 INCOMPLETE. No network requests go to public IP addresses; the checker accepts only a specified HTTP loopback origin. Logs are checked for API metadata, not copied to the test report.

## Guarded EXE build — ONLY after PASS

```powershell
.\.venv-win\Scripts\python.exe .\release_final\build_release.py --root "." --gate ".\release_final_gate.json" --check-only

.\.venv-win\Scripts\python.exe .\release_final\build_release.py --root "." --gate ".\release_final_gate.json"
```

The guarded builder checks that critical checks passed and that tracked application source has not changed since testing. It invokes your **existing** `desktop_packaging/build_complete_exe.py` and `smoke_complete_exe.py`. It does not ship or sign your EXE. Complete the manual checklist in `release_final/MANUAL_ACCEPTANCE.md` **on the packaged EXE**, on an isolated test machine before distribution.

## Local reference verification performed before delivery

See `release_final/REFERENCE_TEST_RESULTS.md`. The package itself and F5 reference implementation have been tested in a sandbox, but **the user's complete local project was not uploaded** and its full Windows test suite and EXE could not be executed here.
