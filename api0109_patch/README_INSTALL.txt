API-010.9 — Deeper Snort / Suricata Configuration Assessment (PDF-first)
=======================================================================

This is an ADDITIVE PATCH, not a full replacement project.
PREREQUISITE: API-010.8 must already be installed and working in this
same project folder. The 010.9 installer refuses to modify project
files if API-010.8 or the expected frontend PDF/route anchors are missing.

--- PowerShell on Windows ---

1) Change to the project root:

  cd "C:\IoT\Information security\project 2\config analyzer"

2) Extract the ZIP. Change the Downloads path if your ZIP is elsewhere.

  Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-010.9-IDS-Deep-Review-PDF-First.zip" -DestinationPath "." -Force

3) VERIFY extraction BEFORE installation:

  Test-Path .\api0109_patch\scripts\install_all_api_010_9.py

Expected: True

4) One-command installation: BOTH backend and frontend/PDF are preflighted
   before any project files are written:

  .\.venv-win\Scripts\python.exe .\api0109_patch\scripts\install_all_api_010_9.py "."

5) Standalone patch tests (no pytest-asyncio add-on needed):

  .\.venv-win\Scripts\python.exe -m pytest -q .\api0109_patch\tests .\api0109_patch\frontend_patch\tests

6) Tests copied to the installed project:

  .\.venv-win\Scripts\python.exe -m pytest -q .\tests\test_api_010_9_ids_configuration.py

7) Full regression tests:

  .\.venv-win\Scripts\python.exe -m pytest -q

8) TypeScript build (from project root):

  cd frontend
  npm run build
  npm run dev

9) Backend in a separate terminal (from project root):

  .\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000

The generated FastAPI /docs should now expose:
  POST /api/v1/analyze/ids-configuration

VERIFY
------
- Existing Dashboard navigation, KPI cards, previous compact reviews,
  and score/previous findings remain unchanged.
- On Snort/Suricata uploads, one extra compact IDS review panel shows
  counters and at most TWO short kind-label snippets, no detailed analysis.
- Detailed line-numbered findings, scope limits and recommendations are
  in the PDF only.
- On ASA/FortiOS, the IDS review is not applicable and the compact card
  does not render; previous NAT/object/service reviews remain in place.
- No active probes, rule execution, remote file reads or YAML/Lua evaluation.

IF PyYAML IS MISSING
-------------------
Suricata review will return "limited" without inventing analysis.
Install PyYAML in the backend virtual environment if required:

  .\.venv-win\Scripts\python.exe -m pip install PyYAML

REVERT
------
From the project root:

  .\.venv-win\Scripts\python.exe .\api0109_patch\scripts\rollback_api_010_9.py "."

This restores first-install backups of modified files. Newly-added
modules (without backups) are left present but not imported by the
restored main.py. Restart FastAPI and rebuild React.

NOTES
-----
- Tests verify the standalone patch and synthetic API-010.8 layouts.
- Your live local Windows application has NOT been accessed or tested.
- Local modifications may cause a fail-before-write preflight error;
  share the actual error rather than force-editing app/api/main.py.
- Verify API-010.8 is installed first. The 010.8 ZIP must be EXTRACTED;
  a download in Downloads alone does not install anything.
