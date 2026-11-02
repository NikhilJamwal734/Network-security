# FirewallAnalyzer — Standalone JSON Logs Viewer (App.tsx-safe)

This installer is specifically for project builds where the previous Logs viewer installer fails with:
`Unsupported App.tsx: Dashboard lazy import was not found exactly once`.

The existing `frontend/src/App.tsx`, dashboard, sidebar, findings pages, PDF code, and original JSON log files remain **unchanged**. The result is a JSONL-style view that colours keys, event status, strings, and numbers. No cards or severity counters are added.

## Install from the main project folder in Windows PowerShell

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-JSON-Logs-Standalone-Installer.zip" -DestinationPath . -Force
.\.venv-win\Scripts\python.exe .\json_logs_standalone_patch\scripts\install_json_logs.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\json_logs_standalone_patch\tests
```

The backend has to be restarted after installation:

```powershell
.\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000 --reload
```

Open a **second terminal**, then:

```powershell
cd .\frontend
npm run dev
```

Open **http://localhost:5173/logs.html** (or the port Vite prints, e.g. 5174).

The endpoint `http://127.0.0.1:8000/api/v1/logs?stream=security_analysis` must respond to a browser on the same local machine.

### PowerShell-only JSON colours

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Watch-FirewallLogs.ps1 -Stream security_analysis
```

### Rollback

```powershell
.\.venv-win\Scripts\python.exe .\json_logs_standalone_patch\scripts\install_json_logs.py "." --rollback
```

The installer will refuse rollback if any installed file was edited afterward (so it cannot silently discard your changes).

## Important limitations

- `logs.html` is a **separate Vite development page**, not a new sidebar item. This is deliberate to avoid altering your customized React navigation.
- Vite's default production build includes `index.html`, not necessarily `logs.html`. For the packaged EXE, add the page as a multi-page Vite build entry or integrate `Logs.tsx` into your existing app using its actual route/navigation structure.
- This viewer needs the existing structured logging patch in `app/core/audit_logging.py`. It does **not** generate audit logs by itself.
- Backend may require CORS allowing the local frontend origin (e.g. `http://localhost:5173`).
- Only access it locally: the API refuses remote peers and remote browser origins. Do not expose the logs publicly without authentication and authorization.
- Source filenames may contain sensitive information; keep log files private.
- If you already have `app/api/log_viewer.py` or `frontend/src/pages/Logs.tsx` with different contents, the installer **refuses to overwrite** them. It does not attempt to reconcile custom edits.
