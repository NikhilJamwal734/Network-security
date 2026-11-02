API-011.6 — Security Hardening & Input Validation (PDF First)
============================================================
Prerequisite: API-011.4 installed. API-011.5 is NOT required by this patch.
This patch DOES NOT add new dashboard cards or revive previously removed cards.

From your Windows PROJECT ROOT (not frontend):

1. Extract API-011.6-Security-Hardening-PDF-First.zip to the current directory.
2. Verify extraction:
   Test-Path .\api0116_patch\scripts\install_all_api_011_6.py
3. Install:
   .\.venv-win\Scripts\python.exe .\api0116_patch\scripts\install_all_api_011_6.py "."
4. Tests:
   .\.venv-win\Scripts\python.exe -m pytest -q .\api0116_patch\tests
   .\.venv-win\Scripts\python.exe -m pytest -q
5. Optional localhost upload smoke test (with backend running):
   .\.venv-win\Scripts\python.exe .\api0116_patch\scripts\smoke_test_api_011_6.py --file "configs\firewall.conf" --platform cisco_asa
6. Frontend:
   cd frontend
   npm run build
   npm run dev

New endpoint: POST /api/v1/analyze/hardened
Input: multipart 'file', optional query 'platform'. Accepted platforms:
  cisco_asa, fortios, snort, suricata (or omit to auto-detect as supported upstream).
Response: previous report fields + 'input_security_review' on success.

Rejects: empty files, binary/archives, malformed UTF-8, suspicious paths in
filenames, unsupported explicit platform, files over 8 MiB, excessively long
lines or over 250000 lines. Rejects without passing the content to the
analysis engine. Never includes user input in error messages.

Important limitations:
- Older endpoints are not disabled and are not protected by this new handler.
- ASGI/framework multipart parsing takes place before API-011.6 handler. Add
  server/reverse-proxy request-size limits in deployment for full protection.
- Text checks cannot guarantee that content is harmless or that every parser
  has strict CPU/memory limits. Isolated runtime and timeout/quotas remain needed.
- No scoring or existing security findings are modified. Previous PDF reviews
  remain present; upload-validation details appear in the PDF only.

Rollback before editing installed files:
  .\.venv-win\Scripts\python.exe .\api0116_patch\scripts\rollback_api_011_6.py "."

Installation is idempotent. No network calls or new runtime dependencies.
The actual Windows build, tests, and analysis of representative input files
still must be verified in the user's project checkout.
