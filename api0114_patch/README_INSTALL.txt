API-011.4 — Pipeline Integration Checks and Local Smoke Test
==========================================================

Prerequisite: API-011.3 installed successfully. Run from the project root,
not from the frontend directory. Extract the ZIP to the project root first.

1) Extract ZIP into the current project root:
   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-011.4-End-to-End-Pipeline-Tests-PDF-First.zip" -DestinationPath "." -Force

2) Verify the script exists:
   Test-Path .\api0114_patch\scripts\install_all_api_011_4.py

3) Install backend + frontend atomically-as-practical:
   .\.venv-win\Scripts\python.exe .\api0114_patch\scripts\install_all_api_011_4.py "."

4) Run patch tests (from project root):
   .\.venv-win\Scripts\python.exe -m pytest -q .\api0114_patch\tests .\api0114_patch\frontend_patch\tests

5) Run the whole backend suite:
   .\.venv-win\Scripts\python.exe -m pytest -q

6) Build frontend:
   cd frontend
   npm run build
   cd ..

7) Optional actual localhost upload smoke test: start your existing FastAPI
   app using your normal command and open another PowerShell terminal in root:
   .\.venv-win\Scripts\python.exe .\api0114_patch\scripts\smoke_test_api_011_4.py --file "configs\firewall.conf" --platform cisco_asa
   Change file/platform to a real supported sample. Test defaults to
   localhost:8000; use --url http://127.0.0.1:YOUR_PORT as needed.

8) Browser export validation is separate: generate a PDF in the UI, run
   the API-011.3 saved-file audit, and visually inspect output.

Rollback ONLY if no installed files have changed:
   .\.venv-win\Scripts\python.exe .\api0114_patch\scripts\rollback_api_011_4.py "."

Preserves all earlier review sections, scores, risk ratings, Findings page,
configuration samples and browser PDF validation. The Dashboard only gets a
compact metric/snippet card; full review detail belongs in PDF.
