API-010.4 — Correlation Evidence & Ordering Review
===================================================

This patch assumes API-010.3 is installed and its CLOSED-UPLOAD fix is working.
It does not alter the restored sidebar colours, existing PDF theme or scoring.

1) Open PowerShell in YOUR PROJECT ROOT:

   cd "C:\IoT\Information security\project 2\config analyzer"

2) Extract the ZIP into that project folder (adjust Downloads path if needed):

   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-010.4-Correlation-Assurance.zip" -DestinationPath "." -Force

3) Install backend (explicitly pass "." so the right root is used):

   .\.venv-win\Scripts\python.exe .\api0104_patch\scripts\install_api_010_4.py "."

4) Install frontend (DO NOT edit original sidebar stylesheet):

   .\.venv-win\Scripts\python.exe .\api0104_patch\frontend_patch\scripts\install_api_010_4_frontend.py ".\frontend"

5) Run tests from PROJECT ROOT:

   .\.venv-win\Scripts\python.exe -m pytest -q tests\test_api_010_4_assurance.py api0104_patch\tests\test_api_010_4_installer.py api0104_patch\frontend_patch\tests\test_installer.py

   .\.venv-win\Scripts\python.exe -m pytest -q

6) Run frontend build:

   cd frontend
   npm run build
   npm run dev

7) Restart backend in a SEPARATE TERMINAL (or rely on --reload):

   cd "C:\IoT\Information security\project 2\config analyzer"
   .\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000

8) Verify http://127.0.0.1:8000/docs lists:

   POST /api/v1/analyze/correlation-assurance

The backend installer aborts if the earlier API-010.3 closed-upload correction
is absent. Both installers check preconditions before writing and create backups
with suffix `.before_api0104.bak`.

TESTS VERIFIED IN ISOLATED WORKSPACE: see ChatGPT response. Production Windows
build and full project's test suite are not verified here.

See api0104_patch/docs/API-010.4.md for safety, supported checks and rollback.
