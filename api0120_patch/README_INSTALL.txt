API-012.0 — FINAL RELEASE VERIFICATION & PRODUCTION READINESS GATE
================================================================
Prerequisite: API-011.6 installed. API-011.5 is optional / not required.
No Dashboard cards, Findings pages or PDF content are changed by this patch.
This stage DOES NOT claim the application is safe for Internet exposure.

WINDOWS POWERSHELL — run from the PROJECT ROOT (not frontend)

1) Extract API-012.0-Final-Release-Gate.zip to your project root.

2) Confirm installer exists:
   Test-Path .\api0120_patch\scripts\install_all_api_012_0.py

3) Install API-012.0:
   .\.venv-win\Scripts\python.exe .\api0120_patch\scripts\install_all_api_012_0.py "."

4) Run patch tests:
   .\.venv-win\Scripts\python.exe -m pytest -q .\api0120_patch\tests

5) Read-only inspection (reports INCOMPLETE if tests, build, PDF and smoke not provided):
   .\.venv-win\Scripts\python.exe .\api0120_patch\scripts\release_gate.py --root "."

6) Full LOCAL verification (use the actual saved PDF path and a safe sample config;
   backend must be running for the optional localhost smoke test):
   .\.venv-win\Scripts\python.exe -m pip install pypdf httpx
   .\.venv-win\Scripts\python.exe .\api0120_patch\scripts\release_gate.py --root "." --run-tests --run-frontend-build --pdf "C:\path\to\downloaded-report.pdf" --smoke-file ".\configs\firewall.conf" --platform cisco_asa --json-out ".\reports\api0120_release_gate.json"

The smoke test is self-contained in api0120_patch/scripts/smoke_test.py.
It never connects outside localhost and does not print upload contents.

The local gate returns exit code:
   0 — all requested local checks completed and passed
   1 — at least one validation failed
   2 — some validation was not run
The application is NEVER labeled production_ready=true by this tool.

7) Verify endpoint with a running backend:
   http://127.0.0.1:8000/api/v1/release/status
   Response: {"release":"12.0","status":"installed", "production_ready":false, ...}

8) Roll back if required BEFORE manually changing the installed router/module:
   .\.venv-win\Scripts\python.exe .\api0120_patch\scripts\rollback_api_012_0.py "."

The installer is idempotent and fail-closed. It changes ONLY:
   app/api/main.py (one import + router registration)
   app/api/release_status.py (new minimal metadata endpoint)
It creates a per-project install manifest and backup. No frontend source is edited.

Tests use the CORRECT import: from fastapi.testclient import TestClient
If VS Code still flags it, select your .venv-win Python interpreter and check
whether fastapi/httpx are installed in that exact environment.

SECURITY LIMITS
- Existing legacy endpoints may remain exposed and bypass API-011.6 input limits.
- No automatic authentication, network gateway or TLS configuration is installed.
- PDF extraction is not visual rendering, nor validation of finding correctness.
- Performance/large-configuration benchmarks (the skipped 011.5 stage) are NOT
  completed by this stage.
- Deployment needs reverse-proxy body limits, process quotas, least privileges,
  authentication / network isolation, logging policies, TLS where necessary,
  recovery backups and offline dependency review.

See docs/RELEASE_CHECKLIST.md for operator sign-off criteria.
