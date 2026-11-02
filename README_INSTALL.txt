FIREWALL ANALYZER DESKTOP EXE — PACKAGED API URL FIX
====================================================

Symptom:
  Platform discovery failed: Failed to fetch. Check the backend at http://127.0.0.1:8000.

Cause:
  The original desktop launcher binds a random available localhost port.
  Some Vite-compiled frontend requests still target 127.0.0.1:8000.

This patch replaces desktop_packaging/desktop_launcher.py with a version
that rewrites the old development API origin in served .js/.mjs/.html assets
so requests target the bound EXE port. No React or API source is modified.
The built frontend files on disk remain unchanged.

1. Close the running FirewallAnalyzer.exe and browser tab.
2. Open PowerShell in your main project root.
3. Extract ZIP into project root (it overwrites the desktop launcher).
4. Run tests:
   .\.venv-win\Scripts\python.exe -m unittest discover -s .\desktop_packaging\tests -p "test_desktop_port_fix.py" -v
5. Rebuild:
   .\.venv-win\Scripts\python.exe .\desktop_packaging\build_exe.py
6. Run:
   .\desktop_release\FirewallAnalyzer\FirewallAnalyzer.exe

Important:
- If it still fails, open the browser DevTools Network tab and inspect the
  exact failed request URL/status; the problem may be a missing API route or
  a missing dynamically imported Python module instead of the port.
- For troubleshooting you can use PowerShell's:
    Invoke-WebRequest http://127.0.0.1:<EXE_PORT>/api/v1/release/status
  replacing <EXE_PORT> with the port printed when you start the EXE.
- The EXE only listens on 127.0.0.1 and must remain open during use.
- The entire output folder, including _internal, must be distributed.
