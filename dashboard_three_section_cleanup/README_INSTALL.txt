DASHBOARD — REMOVE THREE REVIEW SECTIONS (FRONTEND ONLY)
==========================================================

Removes ONLY these visible dashboard sections:
  1. PDF export readiness (API-011.3)
  2. End-to-end pipeline checks (API-011.4)
  3. Configuration review evidence (subsection inside Configuration review)

Preserves:
  - Configuration review summary, score, coverage and priority
  - Other Dashboard metric cards, severity distribution and colored headings
  - Findings pane
  - React API response types and API endpoint
  - Backend analysis and Python tests
  - ALL detailed PDF report content, PDF export verification and download behavior

This patch does not remove source components, CSS or backend features; it removes
only their dashboard rendering and unused imports, allowing simpler rollback.

INSTALL FROM POWERSHELL PROJECT ROOT
-----------------------------------
cd "C:\IoT\Information security\project 2\config analyzer"

# Extract the downloaded zip from Downloads
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\Dashboard-Remove-Three-Review-Sections.zip" -DestinationPath "." -Force

# Preview the changes (does NOT modify files)
.\.venv-win\Scripts\python.exe .\dashboard_three_section_cleanup\scripts\install_dashboard_section_cleanup.py ".\frontend" --dry-run

# Apply cleanup
.\.venv-win\Scripts\python.exe .\dashboard_three_section_cleanup\scripts\install_dashboard_section_cleanup.py ".\frontend"

# Run independent patch tests
.\.venv-win\Scripts\python.exe -m unittest discover -s .\dashboard_three_section_cleanup\tests -p "test_*.py" -v

# Build your frontend
cd frontend
npm run build
npm run dev

ROLLBACK
--------
From your project root:
.\.venv-win\Scripts\python.exe .\dashboard_three_section_cleanup\scripts\install_dashboard_section_cleanup.py ".\frontend" --rollback

Rollback restores only the two source files modified by the cleanup.
Original bytes are stored in frontend/.dashboard_three_section_cleanup_manifest.json.
If either file has been edited after applying the cleanup, rollback will refuse
to overwrite those edits. Keep the manifest until you are sure you won't roll back.

SAFETY / COMPATIBILITY
----------------------
* The installer validates all target files before writing anything.
* Recognized JSX snippets must appear exactly once with their expected import.
* If your current frontend layout differs, the installer stops without changing
  files; do not use broad text replacements to force the patch.
* Existing UTF-8 BOM and CRLF Windows line endings are preserved.
* No third-party Python dependencies required.
* Tests run in an isolated environment. You still need to run npm run build
  on your current Windows project.
