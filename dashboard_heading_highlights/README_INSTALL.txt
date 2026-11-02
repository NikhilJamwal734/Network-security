DASHBOARD HEADING HIGHLIGHTS — UI-ONLY (Compatible with API 011.2)

Purpose
  Make the two Dashboard views' section headings more colorful and visually
  distinct, using a teal/blue/violet/amber accent palette. No analysis logic,
  reviews, reports, Findings pane, severity data, or PDF content is changed.

Install from project root in PowerShell AFTER extracting this ZIP there:

  Test-Path .\dashboard_heading_highlights\scripts\install_heading_highlights.py
  .\.venv-win\Scripts\python.exe .\dashboard_heading_highlights\scripts\install_heading_highlights.py ".\frontend"

Test:

  .\.venv-win\Scripts\python.exe -m unittest discover -s .\dashboard_heading_highlights\tests -p "test_*.py" -v
  cd frontend
  npm run build

What changes:
  frontend/src/pages/UniversalAnalysis.tsx: one CSS import only
  frontend/src/pages/Dashboard.tsx: one CSS import only
  frontend/src/pages/DashboardHeadingHighlights.css: newly added stylesheet

The installer does not change JSX, findings, scripts, API endpoints, or PDFs.
It fails before writing if the expected frontend imports are absent, if the
files are not UTF-8, or if the stylesheet is different from an existing one.
It preserves BOM/CRLF and is safe to rerun. It backs up both TSX files before
changing them with suffix .before_heading_highlights.bak.

Undo from project root:
  .\.venv-win\Scripts\python.exe .\dashboard_heading_highlights\scripts\rollback_heading_highlights.py ".\frontend"

The rollback surgically removes only the CSS imports and the new stylesheet,
without overwriting subsequent custom edits to Dashboard source files.

If your local Dashboard uses different component paths, stop and show the
installer error; do not force the patch on an unrecognized file layout.
