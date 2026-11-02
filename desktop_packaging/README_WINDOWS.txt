FIREWALL CONFIGURATION ANALYZER — WINDOWS EXE BUILD KIT
========================================================

This kit does not modify app/api/main.py, React code, any API patch,
existing reports, or analysis findings.

Prerequisites:
- Your working API-012.0 project with app/api/main.py
- Your .venv-win Python environment containing FastAPI and backend dependencies
- Node/npm on the BUILD computer only
- Windows for creating a Windows executable

OPEN WINDOWS POWERSHELL AT THE MAIN PROJECT ROOT (NOT frontend):
  cd "C:\IoT\Information security\project 2\config analyzer"

Extract the build kit ZIP into this folder, producing desktop_packaging/.

1. Validate that your current project builds correctly:
  .\.venv-win\Scripts\python.exe -m pytest -q
  npm --prefix frontend run build

2. Install the packager and the server in the same environment:
  .\.venv-win\Scripts\python.exe -m pip install pyinstaller uvicorn

3. Create the packaged executable:
  .\.venv-win\Scripts\python.exe .\desktop_packaging\build_exe.py

4. Run it:
  .\desktop_release\FirewallAnalyzer\FirewallAnalyzer.exe

5. Copy ALL of desktop_release\FirewallAnalyzer\ to the destination PC.
   The destination PC does not need Python, Node or npm installed.
   The .exe starts a loopback-only FastAPI server and opens the browser.
   The console stays open while the app runs; Ctrl+C stops the server.

THIS IS A DESKTOP LAUNCHER WITH A BROWSER UI, NOT AN EMBEDDED NATIVE WEBVIEW.
It bundles the compiled React UI and Python backend in one folder.

NOTES / LIMITATIONS
- Keep the full folder together: onedir is more dependable than onefile.
- It does not automatically make remote/network deployment secure.
- Sensitive uploaded configurations and reports need user-data storage policies.
- Some backend code may use paths relative to app files; these resolve into
  the packaged resource directory. Audit any report writes before installing
  under Program Files. Writable output should use a per-user data directory
  such as %LOCALAPPDATA%\FirewallAnalyzer.
- Do not bundle .venv-win, node_modules, original sensitive configs/reports,
  API patch ZIP archives, or secrets into the distribution.
- Always test with safe Cisco ASA, FortiOS, Snort and Suricata samples.
- The exact runtime FastAPI entry point is assumed to be app.api.main:app,
  consistent with API-012.0's router installer. If your checkout differs,
  adjust the import in desktop_launcher.py.
- PyInstaller packages the dependencies that are available in the active
  build Python environment; missing dynamic imports may need extra hooks.
- The launcher chooses an available localhost port and keeps all API URLs
  relative to that origin. No Node/Vite development server is necessary.
