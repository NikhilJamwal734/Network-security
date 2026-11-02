API-011.3 — PDF EXPORT READINESS, RENDERED-BYTE CHECKS & SAVED-PDF AUDIT

PREREQUISITE: API-011.2 backend and frontend successfully installed.
The latest Dashboard visual tweaks and removal of duplicate Security Findings remain unchanged.

1. Extract this ZIP into the PROJECT ROOT (not frontend).
   cd "C:\IoT\Information security\project 2\config analyzer"
   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-011.3-PDF-Export-Integrity-PDF-First.zip" -DestinationPath "." -Force

2. Verify the installer:
   Test-Path .\api0113_patch\scripts\install_all_api_011_3.py
   Expected: True

3. Install BACKEND + FRONTEND in one command from PROJECT ROOT:
   .\.venv-win\Scripts\python.exe .\api0113_patch\scripts\install_all_api_011_3.py "."

4. Test the stage (the optional pypdf/reportlab tests skip if unavailable):
   .\.venv-win\Scripts\python.exe -m pytest -q .\api0113_patch\tests .\api0113_patch\frontend_patch\tests
   .\.venv-win\Scripts\python.exe -m pytest -q
   cd frontend
   npm run build

5. From the app, analyze a config and download the PDF. The browser verifies
   generated PDF byte header, end-of-file marker, size, and page count before
   initiating the download. Browser controls can still block file saving.

6. Optional INDEPENDENT audit of a SAVED exported PDF (from PROJECT ROOT):
   .\.venv-win\Scripts\python.exe -m pip install pypdf
   .\.venv-win\Scripts\python.exe .\api0113_patch\scripts\audit_saved_pdf.py "C:\path\to\report.pdf" --require-11-3

ROLLBACK (only if no installed files have been changed afterward):
   .\.venv-win\Scripts\python.exe .\api0113_patch\scripts\rollback_api_011_3.py "."

ENDPOINT: POST /api/v1/analyze/pdf-readiness
RESPONSE: all prior normalized fields + pdf_export_review.
Dashboard: four counts and no more than TWO short labels; no detailed evidence.
PDF: full (bounded) preflight observations and limitations.
Saved PDF audit: independent pypdf parsing, page count, extractable headings and
page footers. This still does NOT verify visual clipping, font fidelity, that a
user successfully saved the file, or whether security findings are correct.

Prevents accidental double-application, refuses overwrite of customized new
files, creates per-file .before_api0113.bak and a project-root SHA-256 manifest.
No existing findings, scores, severities, or earlier PDF sections are removed.
