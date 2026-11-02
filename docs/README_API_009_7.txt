API-009.7 — Multi-Platform React Frontend (Cisco ASA / FortiOS / Snort / Suricata)

1. Extract this ZIP to your project root:
   C:\IoT\Information security\project 2\config analyzer
2. Run:
   .\.venv-win\Scripts\python.exe scripts\wire_api_009_7_frontend.py
3. Run:
   .\.venv-win\Scripts\python.exe -m unittest discover -s frontend_checks -p "check_*.py" -v
   npm run build
   .\.venv-win\Scripts\python.exe -m pytest -q
4. Start FastAPI and Vite and open http://localhost:5173.

The Python script modifies only src/App.tsx, backing it up first.
It safely refuses unknown App versions instead of overwriting your custom UI.
Existing backend tests should remain at the user-verified 730-pass baseline.
See docs/API-009.7.md for complete instructions and caveats.
