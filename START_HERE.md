# F5 BIG-IP — PDF section 06 professional heading

This patch only edits the **text of section 06's title** in `frontend/src/utils/normalizedPdf.ts`:

**Before:** `F5 BIG-IP Phases 1 + 2 - Detailed technical evidence`

**After:** `F5 BIG-IP LTM & Advanced WAF - Detailed Technical Evidence`

It intentionally leaves the subheading `F5 PHASES 1 + 2 COVERAGE LIMITATIONS` and all analysis/PDF logic unchanged. It is independent of API/backend changes.

## Install (PowerShell; project root)

```powershell
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-F5-PDF-Section06-Heading-Fix.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\f5_pdf_section06_fix\scripts\update_heading.py . --dry-run
.\.venv-win\Scripts\python.exe .\f5_pdf_section06_fix\scripts\update_heading.py .
.\.venv-win\Scripts\python.exe -m unittest discover -s .\f5_pdf_section06_fix\tests -p 'test_*.py' -v
cd frontend
npm run build
cd ..
```

Generate a fresh F5 report in the UI to see the new title. Existing PDF files do **not** change automatically.

## Rollback

```powershell
.\.venv-win\Scripts\python.exe .\f5_pdf_section06_fix\scripts\update_heading.py . --rollback
```

The installer refuses unexpected source versions, preserves BOM and line endings byte-for-byte, and stores a SHA-256 guarded backup without overwriting any existing backup. If you have modified the generator after patching, the rollback refuses to erase your changes.

This is a **source-code change**: rerun the active release gate before generating a distributable EXE. Rebuild the EXE after a passing gate, or it will keep using the previous frontend bundle.
