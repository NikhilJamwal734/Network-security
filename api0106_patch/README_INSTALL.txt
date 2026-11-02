API-010.6 — OBJECT REFERENCE INTEGRITY (BACKEND + FRONTEND)
===========================================================

Prerequisite: API-010.5 already installed, running and verified.
This is an additive patch. Existing dashboards, sidebar colours, PDF styling,
assessment scores and rule-correlation results must remain unchanged.

1. Open PowerShell in your exact project root:

   cd "C:\IoT\Information security\project 2\config analyzer"

2. Extract API-010.6-Object-Integrity.zip into that directory:

   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-010.6-Object-Integrity.zip" -DestinationPath "." -Force

3. Apply backend patch (explicit root argument avoids earlier path errors):

   .\.venv-win\Scripts\python.exe .\api0106_patch\scripts\install_api_010_6.py "."

4. Apply frontend patch:

   .\.venv-win\Scripts\python.exe .\api0106_patch\frontend_patch\scripts\install_api_010_6_frontend.py ".\frontend"

5. Run targeted tests:

   .\.venv-win\Scripts\python.exe -m pytest -q .\tests\test_api_010_6_object_assurance.py
   .\.venv-win\Scripts\python.exe -m pytest -q .\api0106_patch\tests\test_api_010_6_installer.py .\api0106_patch\frontend_patch\tests\test_installer.py

6. Run full backend suite (includes old milestone tests):

   .\.venv-win\Scripts\python.exe -m pytest -q

7. Build the React frontend:

   cd frontend
   npm run build
   npm run dev

8. Restart backend in a separate PowerShell terminal in PROJECT ROOT:

   .\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000

9. Check http://127.0.0.1:8000/docs and look for:

   POST /api/v1/analyze/object-assurance

   Upload a known Cisco ASA or FortiOS configuration to verify the new
   "Object reference integrity" panel and matching PDF appendix.

INSTALLER AND ROLLBACK
----------------------
- Both installers validate expected API-010.5 anchors before writing anything.
- The installers can be run repeatedly without duplicating code.
- Each modified original file is backed up once next to itself as
  <filename>.before_api0106.bak.
- To rollback: stop the servers, restore each *.before_api0106.bak to its
  corresponding original filename, and delete only the *new* API-010.6 files:
  app/api/object_assurance.py
  app/core/object_assurance.py
  tests/test_api_010_6_object_assurance.py
  frontend/src/components/ObjectAssurancePanel.tsx
  frontend/src/components/ObjectAssurancePanel.css
  Then rebuild/restart. The copied app/api/main.py and frontend files must be
  restored from their backups as well (not just the five new files removed).

The original object-resolution endpoint and older APIs remain registered.
This patch neither changes the old reported risk score nor auto-remediates rules.
