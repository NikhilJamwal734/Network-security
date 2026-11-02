API-011.2 — Report Validation and Reporting Reliability (PDF First)

PREREQUISITE: Successful API-011.1 installation.

Extract ZIP into PROJECT ROOT (not frontend). Verify:
  Test-Path .\api0112_patch\scripts\install_all_api_011_2.py

Run from PROJECT ROOT in Windows PowerShell:
  .\.venv-win\Scripts\python.exe .\api0112_patch\scripts\install_all_api_011_2.py "."
  .\.venv-win\Scripts\python.exe -m pytest -q .\api0112_patch\tests .\api0112_patch\frontend_patch\tests
  .\.venv-win\Scripts\python.exe -m pytest -q
  cd frontend
  npm run build

Endpoint: POST /api/v1/analyze/report-validation
Response: all preceding fields + report_validation_review.
Dashboard: four totals and up to TWO short discrepancy names.
PDF: complete bounded check results, expected/observed status, explanations,
analyst actions, limitations. Not a PDF byte/render fidelity test.

Rollback, from project root:
  .\.venv-win\Scripts\python.exe .\api0112_patch\scripts\rollback_api_011_2.py "."

No existing security score, finding, rating, older review or PDF section is
removed or intentionally altered. Backup files have .before_api0112.bak.
