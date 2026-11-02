API-011.0 — CROSS-REVIEW EVIDENCE CONSOLIDATION (PDF-first)
============================================================

ADDITIVE PATCH — NOT A FULL APPLICATION
PREREQUISITE: API-010.9 installed. The 21 010.9 standalone patch tests
passing is useful but does NOT establish the new endpoint is installed.

POWERSHELL (project root)
-------------------------
cd "C:\IoT\Information security\project 2\config analyzer"

# 1. Extract ZIP from Downloads to the current project root.
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-011.0-Consolidation-PDF-First.zip" -DestinationPath "." -Force

# 2. Verify it was extracted.
Test-Path .\api0110_patch\scripts\install_all_api_011_0.py
# Expected True. If False, locate the downloaded archive and check extraction.

# 3. Check 10.9 API prereq before writing.
Test-Path .\app\api\ids_configuration.py

# 4. One command for preflight + backend + frontend + PDF.
.\.venv-win\Scripts\python.exe .\api0110_patch\scripts\install_all_api_011_0.py "."

# 5. Run 011.0 patch tests and installed backend tests.
.\.venv-win\Scripts\python.exe -m pytest -q .\api0110_patch\tests .\api0110_patch\frontend_patch\tests
.\.venv-win\Scripts\python.exe -m pytest -q .\tests\test_api_011_0_consolidation.py

# 6. Run full regression suite and build frontend.
.\.venv-win\Scripts\python.exe -m pytest -q
Push-Location .\frontend
npm run build
Pop-Location

# 7. Restart existing dev processes, and check FastAPI /docs:
# POST /api/v1/analyze/consolidated (multipart file, optional platform)

EXPECTED:
- Earlier normalized findings, scores and analysis modules unchanged.
- Previous dashboard panels retained. New one is summary-only (counts and
  at most two short kind labels). No full evidence/remediation on dashboard.
- All cross-review inventory, provenance, candidate links, limits and
  recommendations appear exclusively in the downloadable PDF.
- No changes to device configuration, no runtime sensor/probe operations.
- One device/sensor at a time; cross-platform means common report schema,
  not analysis of multiple devices together.

ROLLBACK (requires backups from original install):
.\.venv-win\Scripts\python.exe .\api0110_patch\scripts\rollback_api_011_0.py "."

The rollback restores the four modified integration files. New engine and
component files remain unused on disk; delete manually after ensuring they
have not been altered. Do not use rollback if you intentionally edited those
integration files after installing 011.0; compare backups first.

VALIDATION NOTES:
Tests bundled with the patch run against synthetic fixtures. They are not
proof of compatibility with a modified real installation. If the installer
refuses an expected anchor, it changes no files: share the exact error.
