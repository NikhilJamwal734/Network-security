# FirewallAnalyzer — Colour-Coded Logs Page (API-012.0)

**Prerequisites:** Existing Python/FastAPI backend `app/api/main.py`, API 12 release status route, structured logging installed in `app/core/audit_logging.py`. Optional safe-filename upgrade is supported. Existing React/Vite frontend `frontend/src/App.tsx` with Dashboard navigation.

## Install (PowerShell from project root)

```powershell
Expand-Archive "$env:USERPROFILE\Downloads\FirewallAnalyzer-Color-Logs-Viewer.zip" -DestinationPath . -Force
.\.venv-win\Scripts\python.exe .\log_viewer_patch\scripts\install_log_viewer.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\log_viewer_patch\tests
```

Restart backend:

```powershell
.\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000 --reload
```

In a separate terminal restart frontend:

```powershell
cd .\frontend
npm run dev
```

Open the frontend and select **Logs** from the sidebar, or request:

`http://127.0.0.1:8000/api/v1/logs?stream=security_analysis&limit=100`

**Colourful PowerShell** (project root):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Watch-FirewallLogs.ps1 -Stream security_analysis
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Watch-FirewallLogs.ps1 -Stream upload_audit
```

Color is a display concern; original JSONL audit log files are not modified.

## Security & limits

- This is a **local-only endpoint**, not designed for multi-user or public network deployment. Client IP must be a literal loopback IP, and any HTTP Origin must be loopback. Do **not** expose it through a reverse proxy or publish it without authentication, authorization, and CSRF protection.
- No raw configuration data is returned or saved by the viewer. The existing logger may record safe uploaded filenames, which can themselves reveal sensitive information.
- Only five named categories are allowed. No arbitrary filesystem paths or arbitrary log filenames.
- Up to 500 events per API request, most recent first, including rotated backups. The page requests 200 and polls at most every five seconds.
- The viewer does **not** log individual vulnerabilities or colour them CRITICAL/HIGH/MEDIUM/LOW. These remain in Findings. This viewer colours only operational outcomes: ERROR/WARNING/SUCCESS/INFO.
- Browser CORS configuration still governs whether the local Vite frontend can access the API. Use the same API base URL as the existing app.
- You may need to rebuild the Windows EXE (and include the new Python module + compiled frontend) after validation. Only view logs from a trusted local session.
- The installer checks for App.tsx patterns known from project versions. If the UI has changed substantially, it stops without writing any files. Then manually import `Logs.tsx`, add a `Logs` navigation item and render `<Logs />`, and register `app.api.log_viewer.router` in FastAPI.

## Rollback

From the project root:

```powershell
.\.venv-win\Scripts\python.exe .\log_viewer_patch\scripts\install_log_viewer.py "." --rollback
```

Rollback will refuse to overwrite later manual edits. Backups and a SHA256 manifest are created under `.log_viewer_patch_backup/` and `.log_viewer_patch_manifest.json`.
