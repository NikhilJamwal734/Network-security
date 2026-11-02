API-010.5 - Network Object Resolution & Policy Selector Review
=============================================================

PREREQUISITE: API-010.4 backend + frontend installed; API-010.3 closed-file upload fix working.
The backend installer REQUIRES app/api/correlation_assurance.py and refuses unknown layouts.
This is an additional advisory endpoint; prior endpoints and scoring are not rewritten.

WINDOWS INSTALLATION (PowerShell)

1. Go to the actual project root (not the parent "project 2" folder):

   cd "C:\IoT\Information security\project 2\config analyzer"

2. Extract the downloaded package:

   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-010.5-Object-Resolution.zip" -DestinationPath "." -Force

3. Install the BACKEND (explicit project directory argument):

   .\.venv-win\Scripts\python.exe .\api0105_patch\scripts\install_api_010_5.py "."

4. Install the FRONTEND (explicit frontend directory argument):

   .\.venv-win\Scripts\python.exe .\api0105_patch\frontend_patch\scripts\install_api_010_5_frontend.py ".\frontend"

5. Run focused tests (do not assume installer tests are copied into project tests/):

   .\.venv-win\Scripts\python.exe -m pytest -q tests\test_api_010_5_object_resolution.py api0105_patch\tests\test_api_010_5_installer.py api0105_patch\frontend_patch\tests\test_installer.py

6. Run all existing tests:

   .\.venv-win\Scripts\python.exe -m pytest -q

7. Verify frontend production build:

   cd frontend
   npm run build
   npm run dev

8. Restart FastAPI in ANOTHER terminal (Ctrl+C in old server terminal first):

   cd "C:\IoT\Information security\project 2\config analyzer"
   .\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000

9. Verify Swagger at http://127.0.0.1:8000/docs:

   POST /api/v1/analyze/object-resolution

Upload an ASA/FortiOS config with named address definitions and supported policy
syntax; the Dashboard includes a new "Network objects and policy selectors"
section. The same summary and candidate pairs appear in the normalized PDF.

SECURITY AND SCOPE
- Supported: ASA IPv4 host/subnet network object; FortiOS IPv4 subnet
  address, non-exclusion address group and basic TCP service custom object.
- No user-supplied file is executed; no network requests or filesystem traversal.
- Unresolved syntax is not guessed or silently replaced with all/any.
- Snort/Suricata variables are labeled NOT ASSESSED by this feature.
- Candidate correlations are not proven effective-policy conflicts and do NOT
  affect prior reports, findings, scores, severity counts or device configs.
- Explicit ordering is advisory; FortiOS policy order is not established.
- Input sample limit: 2 MiB; line limit: 50,000; candidate rules cap 120;
  candidate pairs cap 60. Outputs indicate truncation.
- The current LEFT SIDEBAR styles/colors are not touched. JSON downloads remain
  disabled in the UI as configured by earlier changes.

ROLLBACK
- Each modified file is backed up once as *.before_api0105.bak.
- Restore those backups to their original filenames if necessary.
- Delete newly added app/api/object_resolution.py, app/core/object_resolution.py,
  frontend/src/components/ObjectResolutionPanel.tsx and .css.
- Remove ONLY the API-010.5 import/include_router lines from app/api/main.py,
  and restore frontend src/api/universal.ts, pages/UniversalAnalysis.tsx,
  utils/normalizedPdf.ts from the *.before_api0105.bak copies.
- Restart the backend and frontend after rollback.

Preflight aborts without changing files if it detects an unsupported project
layout. Review api0105_patch/docs/API-010.5.md for syntax and limitations.
