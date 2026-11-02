# Firewall Analyzer — F5 BIG-IP Phase 2 (Windows / FastAPI / React)

## What it adds

The patch extends your **already installed and working** F5 Phase 1 endpoint without changing its URL, your existing vendor registry, your current F5 parser or the dashboard layout.

- **F5-004**: Inspect explicit `security-log-profiles` associations for enabled virtual servers. Missing or `none` associations are **review observations**, not automatically proven vulnerabilities. Some environments use inherited/default/out-of-band logging.
- **F5-005**: Assess UCS encryption only when a separate operator-supplied JSON statement is provided. An asserted unencrypted backup becomes a **MEDIUM finding marked `operator_supplied_unverified`**. Without evidence, the analyzer returns a *not assessed* observation. No UCS archive is read or extracted.
- **F5-006**: Assess supplied signature-update status or report insufficient evidence. No live update lookup, signature download, or runtime verification is attempted.
- **F5-008**: Inventory `ltm rule` (Tcl iRules), associate explicit rule references to virtual servers, and flag selected review indicators. It never runs or reproduces the iRule content.

The existing F5 Phase 1 checks **F5-001, F5-002, F5-003 and F5-007** are retained.

## Files modified by installer

- `app/f5_phase1_addon/api.py` — extend the already working F5 upload response, optional `evidence_json` form field
- `frontend/src/api/f5Phase1.ts` — change visible F5 label to Phases 1 + 2
- `frontend/src/utils/normalizedPdf.ts` — update the existing F5 PDF section description to include Phases 1 + 2

## New files

- `app/f5_phase2_addon/__init__.py`
- `app/f5_phase2_addon/review.py`

The installer leaves `app/parsers/f5_bigip_parser.py`, `app/api/main.py`, `UniversalAnalysis.tsx`, the Inventory page, other vendors, and Logs code untouched.

## Install on Windows (project root)

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-F5-Phase2-FINAL.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\f5_phase2_patch\scripts\install_f5_phase2.py "." --dry-run
.\.venv-win\Scripts\python.exe .\f5_phase2_patch\scripts\install_f5_phase2.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\f5_phase2_patch\tests
```

Expected: five modifications on first install, then `No changes needed` on repeat. Installer aborts if unfamiliar Phase 1 API/PDF/frontend code would be overwritten. Backups are made and verified using SHA-256.

## Run backend and test

```powershell
.\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000 --reload
```

Open another terminal in the project root:

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/analyze/f5/phase1" -F "file=@f5_phase2_patch/examples/f5_phase2_sample.conf"
```

The path is intentionally unchanged because your working React F5 adapter already uses it. The returned object includes `schema_version: f5-phase2-1.0`, expanded `coverage.supported_checks`, updated findings/observations, and optional `f5_phase2_review` metadata. The endpoint also still returns the API-011.6 `input_security_review` and uploaded-file SHA-256.

To supply **explicit operator evidence** for UCS archives and signature update status:

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/analyze/f5/phase1" -F "file=@f5_phase2_patch/examples/f5_phase2_sample.conf" -F "evidence_json=<f5_phase2_patch/examples/f5_phase2_evidence.json"
```

Use the sample JSON schema below (dummy data; **not** evidence about a real device):

```json
{
  "ucs_backups": [{"name": "example-backup.ucs", "encrypted": false}],
  "signature_updates": {"status": "failed", "last_installed": "2026-01-15"}
}
```

`evidence_json` is an optional, at-most-16-KiB form field. It **must not contain passwords or full UCS archives**. The current frontend only sends the configuration file, so its default view shows F5-005/F5-006 as *not assessed*. You can use Swagger or `curl.exe` to submit evidence; the optional evidence-upload UI is not included in this patch.

## Frontend / PDF

```powershell
cd frontend
npm run build
npm run dev
```

Select **F5 BIG-IP (Phases 1 + 2)**, upload the sample `.conf`, review Findings, then download the normal PDF report. The existing normalized F5 adapter accepts the extra F5-004/005/006/008 evidence records and separates `review_observations` from `findings`. Confirm the section **F5 BIG-IP Phases 1 + 2 - Detailed technical evidence** appears in the generated PDF.

If you use a packaged EXE, rebuild it only after source-based integration testing. This ZIP contains code and installer **not a Windows EXE**.

## Roll back

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase2_patch\scripts\install_f5_phase2.py "." --rollback
```

Rollback refuses to run if a patched file was modified later; it will not discard user changes. Do not delete the manifest or `.before_f5_phase2.bak` files before rollback.

## Security limitations

This is static configuration review only. It cannot prove live logging delivery, archive encryption, signature update freshness, active iRule behavior or complete deployed WAF policy. Additional data may be absent from `bigip.conf`. Treat observations as follow-up evidence requests, not confirmed vulnerabilities. If the same user can alter the submitted evidence JSON, that assertion is not independently authenticated.

F5 official references: 
- https://techdocs.f5.com/en-us/bigip-17-0-0/big-ip-asm-implementations/logging-application-security-events.html
- https://techdocs.f5.com/en-us/bigip-16-0-0/big-ip-secure-vault-administration/working-with-ucs-archives.html
- https://techdocs.f5.com/en-us/bigip-15-0-0/big-ip-asm-implementations/updating-security-components.html
- https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-system-irules-concepts-11-6-0/2.html
