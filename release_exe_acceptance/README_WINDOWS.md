# FirewallAnalyzer — Windows EXE Acceptance Runner

This package tests **the actual existing Windows EXE**, not a development FastAPI instance. It does not overwrite your analyzer, frontend, logs, or the binary.

## Prerequisites

1. `desktop_release_single/FirewallAnalyzer.exe` built by the guarded release process.
2. `release_final_build_result.json` from that same build (contains its SHA-256).
3. `release_final/examples/` with the four synthetic vendor fixtures.
4. `f5_phase2_patch/examples/f5_phase2_sample.conf` and `f5_phase3_patch/examples/f5_phase3_evidence.json`.
5. Your project `.venv-win/Scripts/python.exe` to run the acceptance script.

## Installation and execution

Stop any separately running FastAPI/Vite development servers and old FirewallAnalyzer EXE sessions first. Leave the release files and existing audit logs intact.

Extract the ZIP at the existing project root. In PowerShell:

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Test-Path .\desktop_release_single\FirewallAnalyzer.exe
Test-Path .\release_final_build_result.json
.\release_exe_acceptance\Run-Acceptance.ps1
```

If PowerShell blocks local `.ps1` execution, run Python directly (no policy change needed):

```powershell
.\.venv-win\Scripts\python.exe .\release_exe_acceptance\check_exe.py --root "."
```

The script creates `release_exe_acceptance_result.json` and prints results. No raw uploaded configurations, HTTP bodies or log records are saved in that JSON.

## What is verified

- EXE SHA-256 equals the release build receipt (a mismatch fails).
- A **fresh** EXE starts with `--no-browser` and announces a dynamic `127.0.0.1` port. It is **not** assumed to be port 8000.
- Its dashboard HTML and `/api/health` respond with HTTP 200.
- It serves `/logs.html` and `/api/v1/logs?stream=application&limit=1`.
- The real EXE processes synthetic Cisco ASA, FortiOS, Snort and Suricata configurations through `/api/v1/analyze/hardened` with correct platform identities and consistent normalized reports.
- F5's packaged API returns 3 findings/5 observations without evidence, 4 findings/4 observations with JSON, with appropriate confidence labels and an input SHA-256 match.
- `%LOCALAPPDATA%\FirewallAnalyzer\logs\api_access.log` changes during API calls and contains parseable JSON request records. The script does not save these records.
- It sends Windows `CTRL_BREAK_EVENT` to the EXE process group and checks the process exits with code 0 and the HTTP server stops. **If the Windows terminal does not support this signal, the result is INCOMPLETE or FAIL, never a false PASS; perform the manual Ctrl+C test.**

## Interpreting results

- `automated_status: PASS` means all scripted checks passed. **It does not mean final manual acceptance passed.**
- `automated_status: INCOMPLETE` means a required item could not be verified, commonly an unavailable build receipt or graceful shutdown signal.
- `automated_status: FAIL` means at least one check failed. Do not release.
- `manual_ui_acceptance: PENDING` is intentional. See `MANUAL_ACCEPTANCE.md` for browser, PDF, colours, Ctrl+C and clean-VM checks.

This tool performs tests using synthetic configurations only. Run it on your Windows development computer where the EXE was built, and manually test the resulting EXE on a clean VM before distribution. Do not elevate privileges or disable Windows Defender for these tests.

## Local isolated unit tests

```powershell
.\.venv-win\Scripts\python.exe -m unittest discover -s .\release_exe_acceptance\tests -p "test_*.py" -v
```

These isolated unit tests do not launch your EXE, and cannot substitute for the acceptance run.
