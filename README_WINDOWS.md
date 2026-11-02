# FirewallAnalyzer: complete Windows EXE build kit

This kit builds **your current installed project**. It is not itself an executable or a replacement for your analyzer's source. It packages FastAPI, the Python security analysis engine, the compiled React dashboard and any successfully installed logging/JSON Logs viewer features.

## Before building

Use **Windows PowerShell**, in the project directory:

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
```

Back up the project first. **Do not delete** `app`, `frontend`, `logs`, or your patches. The kit only writes to `desktop_packaging/` and builds Vite/PyInstaller output. It creates and then removes a temporary Vite configuration when a standalone Logs page is present.

Verify backend and frontend already work in development and recent tests pass. In particular, the logging-related additions are optional, but they must be fully installed to appear in the packaged EXE.

```powershell
Test-Path .\app\core\audit_logging.py
Test-Path .\app\api\log_viewer.py
Test-Path .\frontend\logs.html
Test-Path .\frontend\src\logs-main.tsx
```

If you want the standalone Logs page, ensure the final three pieces are present and the API router is registered in `app/api/main.py`. The packager will not silently add unfinished logging features to an existing project.

## Build one EXE

Install dependencies in your existing environment if needed:

```powershell
.\.venv-win\Scripts\python.exe -m pip install -U pyinstaller
cd frontend
npm ci
cd ..
```

`npm ci` requires `frontend/package-lock.json`. If the project uses a different package manager, use its normal install command instead.

Check source layout:

```powershell
.\.venv-win\Scripts\python.exe .\desktop_packaging\build_complete_exe.py --check
```

Build the full frontend and bundle the EXE:

```powershell
.\.venv-win\Scripts\python.exe .\desktop_packaging\build_complete_exe.py
```

Output:

```text
desktop_release_single\FirewallAnalyzer.exe
```

This **single EXE** starts the backend on an available `127.0.0.1` port and opens your compiled React dashboard automatically. No separate `npm run dev` or `uvicorn` process is needed on the target machine. Close it by pressing `Ctrl+C` in the executable's console window. The EXE contains compiled code and assets rather than loose project source files, but PyInstaller is **not anti-reverse-engineering protection**.

The optional standalone Logs page, if successfully built, is at the URL printed next to `JSON logs viewer` in the EXE console. The installed log files are written outside the EXE, normally:

```text
%LOCALAPPDATA%\FirewallAnalyzer\logs\
```

If you prefer a folder containing the EXE and dependencies (better diagnostics and sometimes fewer antivirus problems), use:

```powershell
.\.venv-win\Scripts\python.exe .\desktop_packaging\build_complete_exe.py --onedir
```

Distribute the entire `desktop_release_folder\FirewallAnalyzer` folder in that case, not just the `.exe`.

## Smoke test the EXE

```powershell
.\.venv-win\Scripts\python.exe .\desktop_packaging\smoke_complete_exe.py
```

The smoke test starts the EXE with `--no-browser`, validates dashboard and API endpoints, validates the optional JSON Logs page if present, and then shuts it down. The smoke test does *not* replace a real configuration upload, PDF export, or logging verification; perform these manually before sharing.

## Run packaging kit tests

```powershell
.\.venv-win\Scripts\python.exe -m unittest discover -s .\desktop_packaging\tests -p "test_*.py" -v
```

## Troubleshooting

- **Unsupported App.tsx**: This builder does not modify `App.tsx` or install a Logs sidebar. It packages the existing UI and any standalone Logs page already installed.
- **Missing frontend logs.html**: Install/verify the previous JSON Logs standalone patch first. The builder will package it if present and fully integrated.
- **React TypeScript build failed**: Fix the displayed TypeScript errors in your existing source. The script intentionally stops rather than packaging stale `dist` assets.
- **Address 8000 issue**: The launcher rewrites known compiled development origins (`http://127.0.0.1:8000` and `http://localhost:8000`) to the chosen EXE port at response time. An unusual API host setting may need a specific change.
- **WinError 5 / file access denied**: Stop any running `FirewallAnalyzer.exe` processes before rebuilding. Keep antivirus running and inspect its quarantine/history if it blocks the build; do not routinely disable security protections.
- **App-specific report or configuration templates missing**: Review the failing path. This generic packager includes installed Python modules and built frontend; any external runtime template/data resource that your project loads from disk requires an explicit audited data-bundle rule.
- **File already exists: `.firewall-desktop-vite.config.mts`**: The script refuses to overwrite it. Investigate and remove it only if it is a leftover temporary file from your own interrupted build.
- **Logs only in development**: Confirm the logging module is installed and the app registers its routes before building. `logs` and raw uploaded configurations are never embedded in the EXE.

## Packaging limitations and privacy

This is a local loopback application, not an independently audited production installer. The output is **unsigned** unless you sign it separately. The EXE may be large. It contains Python bytecode that a determined user can extract; do not bundle passwords, API keys, or private customer configuration files. No guarantees are made about antivirus classification or compatibility across Windows installations. Verify on a second Windows PC or VM if possible.
