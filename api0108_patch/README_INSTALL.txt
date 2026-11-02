API-010.8 — NAT / Routing / Reachability (snippet Dashboard; PDF evidence)
===========================================================================

Prerequisite: API-010.7 must already be installed and working.
This is an ADDITIVE installer, not a replacement full project.
Do not remove the existing API-010.7, API-010.6, or other features.

1. PowerShell — go to your real project root:

   cd "C:\IoT\Information security\project 2\config analyzer"

2. Extract the ZIP into the root (change Downloads path if necessary):

   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-010.8-NAT-Routing-Reachability-PDF-First.zip" -DestinationPath "." -Force

3. Install the backend. Pass the project root explicitly:

   .\.venv-win\Scripts\python.exe .\api0108_patch\scripts\install_api_010_8.py "."

4. Install the frontend (API endpoint + only one compact card + PDF evidence):

   .\.venv-win\Scripts\python.exe .\api0108_patch\frontend_patch\scripts\install_api_010_8_frontend.py ".\frontend"

5. Test just this patch:

   .\.venv-win\Scripts\python.exe -m pytest -q tests\test_api_010_8_nat_route_reachability.py api0108_patch\tests\test_api_010_8_installer.py api0108_patch\frontend_patch\tests\test_installer.py

6. Run entire project suite, then build React:

   .\.venv-win\Scripts\python.exe -m pytest -q
   cd frontend
   npm run build
   npm run dev

7. Restart FastAPI from another PowerShell terminal at project root:

   .\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000

   http://127.0.0.1:8000/docs should show:
      POST /api/v1/analyze/nat-route-reachability

8. Upload an ASA or FortiOS configuration. Confirm:
   - Previous Dashboard cards stay unchanged.
   - New NAT / routing card contains only counts and at most 2 short labels.
   - PDF contains full NRR source evidence and limitations.
   - Prior object, vendor, ordering, and service/IPv6 evidence persists.
   - Snort/Suricata show this additional review as "Not assessed" without regression.

ROLLBACK
--------
To restore the previous API route, Dashboard and PDF integration:

   .\.venv-win\Scripts\python.exe .\api0108_patch\scripts\rollback_api_010_8.py "."

The rollback restores .before_api0108.bak files and leaves newly-added,
unreferenced modules in place for review. Restart FastAPI and rebuild React.

NOTES
-----
- The patch is verified using its standalone Python tests and installer fixtures.
- Your *complete local project checkout* has not been provided in this chat;
  installation and end-to-end testing on your copy must happen locally.
- This is static, conservative candidate evidence, not live route reachability.
- Do not infer "unreachable" from missing route matches in the uploaded subset.
- The existing sidebar colors, layout, previous 4 compact reviews and
  normalized security metrics are unchanged by these installer scripts.
