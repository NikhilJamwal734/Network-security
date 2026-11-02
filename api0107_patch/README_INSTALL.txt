API-010.7 — Advanced Service Groups and IPv6 (PDF-first presentation)
========================================================================

Prerequisites
-------------
- API-010.6 installed and working; current original Dashboard with four
  compact review sections is recommended.
- The PDF-only formal exporter from your previous upgrades.
- Python .venv-win and Node/Vite frontend dependencies already set up.

1) PowerShell — go to the REAL project root:

cd "C:\IoT\Information security\project 2\config analyzer"

2) Extract the ZIP to the project root:

Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-010.7-Service-Groups-IPv6-PDF-First.zip" -DestinationPath "." -Force

3) Install the backend, passing "." explicitly:

.\.venv-win\Scripts\python.exe .\api0107_patch\scripts\install_api_010_7.py "."

4) Install the frontend:

.\.venv-win\Scripts\python.exe .\api0107_patch\frontend_patch\scripts\install_api_010_7_frontend.py ".\frontend"

5) Run the new backend and installer tests:

.\.venv-win\Scripts\python.exe -m pytest -q tests\test_api_010_7_service_ipv6.py api0107_patch\tests\test_api_010_7_installer.py api0107_patch\frontend_patch\tests\test_installer.py

6) Run the full backend tests and build React:

.\.venv-win\Scripts\python.exe -m pytest -q
cd frontend
npm run build
npm run dev

7) Restart FastAPI in a SECOND terminal:

cd "C:\IoT\Information security\project 2\config analyzer"
.\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000

Verify http://127.0.0.1:8000/docs includes:
  POST /api/v1/analyze/service-ipv6

Upload an ASA or FortiOS configuration with IPv6 or explicit custom service
objects. The Dashboard shows snippets; the PDF shows the full returned
technical evidence, recommendations, object inventory, and limitations.

Rollback (if necessary)
-----------------------
From the project root:

.\.venv-win\Scripts\python.exe .\api0107_patch\scripts\rollback_api_010_7.py "."

This restores backups of app/api/main.py, frontend/src/api/universal.ts,
frontend/src/pages/UniversalAnalysis.tsx and frontend/src/utils/normalizedPdf.ts.
Newly-created, now-unused modules are left on disk for inspection.
Restart FastAPI and rebuild React afterward.

Notes
-----
- Original sidebar colours / layout unchanged.
- Dashboard headline metrics and existing 4 compact reviews unchanged.
- API-010.5 and API-010.6 object panels become compact snippets.
- This is supplementary STATIC checking with deliberately limited syntax.
- It does NOT prove device exposure or alter normalized security scoring.
- Installing on a different/unrecognized frontend layout stops BEFORE edits.
