RESTORE ORIGINAL DASHBOARD + SHORTEN ONLY FOUR REVIEW SECTIONS
===========================================================

Goal
----
Restore the existing Dashboard as it was immediately before
Dashboard-Summary-Detailed-PDF-Upgrade, using YOUR OWN local source backup.
Keep other Dashboard sections, PDF generator, backend, scoring and sidebar intact.

Only these four review panels become short snippets on the Dashboard:
  1. Configuration review evidence (AdvancedAssessmentPanel)
  2. Vendor-specific supplemental/configuration review (VendorDeepReviewPanel)
  3. Rule correlation and conflict review (RuleCorrelationPanel)
  4. Correlation evidence and ordering review (CorrelationAssurancePanel)

The professional PDF keeps ALL the detailed explanations, recommendations,
limitations, evidence and source-line details that its current exporter includes.
This update never modifies normalizedPdf.ts or any other PDF code.

INSTALL ON WINDOWS (PowerShell)
-------------------------------
1. Open project root:
   cd "C:\IoT\Information security\project 2\config analyzer"

2. Extract the downloaded ZIP into this project root:
   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\Restore-Dashboard-Four-Compact-Reviews.zip" -DestinationPath "." -Force

3. Install:
   .\.venv-win\Scripts\python.exe .\dashboard_selective_patch\scripts\install_selective_dashboard.py ".\frontend"

4. Run installer tests:
   .\.venv-win\Scripts\python.exe -m unittest discover -s .\dashboard_selective_patch\tests -p "test_*.py" -v

5. Build and run:
   cd frontend
   npm run build
   npm run dev

The script recognizes whether the full Dashboard compaction is active.
When active, it restores the exact pre-compaction file from:
  frontend\src\pages\UniversalAnalysis.tsx.before_dashboard_pdf_focus.bak

If the backup is missing/invalid, the installer STOPS and changes nothing.
Never substitute the included test fixture for your own dashboard backup.

Before editing the script validates ALL four component layouts, and creates
".before_selective_dashboard.bak" backups for every changed source.
It is safe to run repeatedly and does not need a backend restart.

ROLLBACK THIS UPDATE
--------------------
From the project root:
  .\.venv-win\Scripts\python.exe .\dashboard_selective_patch\scripts\rollback_selective_dashboard.py ".\frontend"

This restores the Dashboard/component state immediately before THIS update,
which may be the full compact Dashboard if that is what you had installed.

IMPORTANT
---------
All source findings and reports are retained. Dashboard snippets show at most
two items per selected section and direct the reader to the PDF for details.
If your professional PDF's server-side data is incomplete, the interface cannot
recover missing details. Prior report limitations and output safety caps apply.

Verified in isolated test workspace: 7 installer tests and strict TypeScript
check of all four changed components. Full user application build not tested.
