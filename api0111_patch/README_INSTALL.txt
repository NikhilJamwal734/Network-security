API-011.1 — Correlation Accuracy / False-Positive Triage (PDF First)

PREREQUISITE: Existing API-011.0 installation completed successfully.

From the PROJECT ROOT in Windows PowerShell, extract this ZIP into the current
folder. The resulting folder must be: .\api0111_patch\

  Test-Path .\api0111_patch\scripts\install_all_api_011_1.py
  .\.venv-win\Scripts\python.exe .\api0111_patch\scripts\install_all_api_011_1.py "."
  .\.venv-win\Scripts\python.exe -m pytest -q .\api0111_patch\tests .\api0111_patch\frontend_patch\tests
  .\.venv-win\Scripts\python.exe -m pytest -q
  cd frontend
  npm run build

Additional endpoint: POST /api/v1/analyze/correlation-accuracy

Response adds only `correlation_accuracy_review`; previous normalized findings,
scoring and review data remain unchanged. Browser dashboard: max two compact
link classifications. All reasons, observations and recommendations: PDF only.

Rollback from project root:
  .\.venv-win\Scripts\python.exe .\api0111_patch\scripts\rollback_api_011_1.py "."

The reviews are static, bounded metadata checks, not verified false positives,
operational reachability, or proof of duplicate root causes.
