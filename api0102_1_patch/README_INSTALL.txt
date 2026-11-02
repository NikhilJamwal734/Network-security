API-010.2.1 — Precision Accuracy Enhancements (NO theme/sidebar changes)
======================================================================

Existing project root:
C:\IoT\Information security\project 2\config analyzer

PREREQUISITE: API-010.2 is installed and backend works.

1. Open PowerShell:
   cd "C:\IoT\Information security\project 2\config analyzer"

2. Extract the ZIP to the CURRENT directory:
   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-010.2.1-Precision-Accuracy-Enhancements.zip" -DestinationPath "." -Force

3. Install (note the explicit dot path):
   .\.venv-win\Scripts\python.exe .\api0102_1_patch\scripts\install_api_010_2_1.py "."

4. Run tests:
   .\.venv-win\Scripts\python.exe -m pytest -q tests\test_api_010_2_1_enhancements.py
   .\.venv-win\Scripts\python.exe -m pytest -q

5. Restart FastAPI (Ctrl+C in backend terminal, then):
   .\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000

6. Open your existing dashboard at http://localhost:5173 and analyze a configuration.
   The existing precision-review panel shows additional findings and richer evidence.
   There are NO frontend file changes, so no npm rebuild is necessary for this patch.

What's improved:
- Cisco ASA: explicit SSHv1; broad ASDM/HTTPS access when http server enabled.
- FortiOS: explicit disabled UTM on enabled accept policies (LOW, advisory).
- Snort: duplicate GID+SID, no false positive when generators differ.
- Suricata: duplicate GID+SID with source-line evidence.
- Evidence now lists occurrence lines for duplicate IDS rule identifiers.

Scope and safeguards:
- Applies ONLY to the existing POST /api/v1/analyze/precision-review endpoint.
- Legacy endpoints, backend scores, frontend styles and PDF layout are untouched.
- Vendor review checks are advisory, not added to formal severity counts or scores.
- Does not execute uploaded configuration or resolve includes/external files.
- Doesn't prove live exposure, policy reachability, or rule activation.

Rollback:
- Stop FastAPI.
- Restore app/core/precision_review.py.before_api0102_1.bak over app/core/precision_review.py.
- Remove app/core/precision_enhancements.py after reverting the import.
- Restart FastAPI. No frontend rollback is needed.
