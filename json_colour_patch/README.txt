FirewallAnalyzer Logs — JSON-STYLE COLOUR ONLY
===============================================
This update replaces ONLY:
  frontend/src/pages/Logs.tsx
  frontend/src/pages/Logs.css

It preserves your existing log categories, filtering, search, auto-refresh,
JSON export, FastAPI endpoint, stored JSON logs, and application navigation.
It removes event cards/summary cards and presents one JSON object per line,
using colour to distinguish keys, strings, numbers, and event statuses.

INSTALLATION (PowerShell from project root):
  Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-JSON-Only-Color-Fix.zip" -DestinationPath . -Force
  .\.venv-win\Scripts\python.exe .\json_colour_patch\scripts\install_json_colour.py "."

Frontend restart:
  cd frontend
  npm run dev

ROLLBACK (from project root):
  .\.venv-win\Scripts\python.exe .\json_colour_patch\scripts\install_json_colour.py "." --rollback

REQUIREMENTS: Must have installed the previous Color-Logs-Viewer package.
The installer refuses unknown customized UI files instead of overwriting them.
Nothing in app/, logs/, App.tsx, the API, or original Log JSON is modified.

NOTE: Your existing log viewer API sanitizes and adds a computed "level" field to
entries before returning them to the UI. The JSON display faithfully shows
those returned entries but is not an exact byte-for-byte view of the on-disk
JSONL files. Stored files remain exactly as they were.
