# FirewallAnalyzer — F5 BIG-IP Phase 1 Frontend + PDF Integration

**Prerequisite:** Your previous F5 Phase 1 backend addon is already installed and the endpoint `POST /api/v1/analyze/f5/phase1` works. This archive is an incremental UI/report patch; it does not re-install or replace Phase 1 backend modules.

## What changes

The installer updates only three frontend paths:

1. `frontend/src/pages/UniversalAnalysis.tsx` — adds F5 BIG-IP (Phase 1) to the current platform selector and routes an explicit F5 selection to the already-working F5 endpoint.
2. `frontend/src/api/f5Phase1.ts` — **new** adapter that validates the F5 result and maps F5 findings into the existing normalized findings and PDF interface. Keeps review observations separate from detected misconfigurations.
3. `frontend/src/utils/normalizedPdf.ts` — appends an **F5 BIG-IP Phase 1 - Detailed technical evidence** section to your existing formal PDF; includes affected F5 object, source line, configured setting, observed value, associated virtual servers, evidence confidence, recommendations and limitations. Your existing SHA-256 upload validation PDF section is untouched.

Existing `app` modules, F5 parser, older vendors, `App.tsx`, navigation, Logs page, logging files, and standalone launcher are not changed by this installer.

## Windows installation

Open PowerShell in the analyzer root (not inside the `frontend` folder):

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-F5-Phase1-Frontend-PDF-Integration.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\f5_phase1_ui_patch\scripts\install_f5_ui.py "." --dry-run
.\.venv-win\Scripts\python.exe .\f5_phase1_ui_patch\scripts\install_f5_ui.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\f5_phase1_ui_patch\tests
cd frontend
npm run build
npm run dev
```

In a **separate terminal**, start the API if it isn't running:

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
.\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000 --reload
```

Open the URL printed by Vite. On the existing upload page, explicitly select **F5 BIG-IP (Phase 1)**, choose the sample `.conf`, analyze, view Findings, and export the formal PDF using the existing button. Check that the PDF includes the F5 technical evidence section.

Sample F5 config from the previous F5 installation:

`f5_phase1_compat_patch/examples/f5_phase1_sample.conf`

Expected **sample** Phase 1 outcome: 3 findings (`F5-001`, `F5-003`, `F5-007`) and 1 separate policy-review observation (`F5-002`), *not a scored security assessment*. This is a controlled fixture, not a scan of a deployed F5 device.

## Important scope and limitations

- This release adds F5 to the **existing frontend selection** only. It does **not** change the backend registry/automatic detection endpoint or other vendors' APIs. F5 must be **explicitly selected** in the UI.
- It does not assess `F5-004`–`F5-008`; that is Phase 2 work.
- F5 `DEFAULT` cipher selection and incomplete certificate evidence are not automatically counted as vulnerabilities. They remain in PDF **Review observations**.
- No actual F5 WAF engine or device is contacted; only the uploaded supported static configuration subset is analyzed.
- Existing 2 MiB frontend upload limit is retained, even if the backend permits a larger file; the UI does not loosen existing upload security controls.
- The existing PDF exporter retains its own safety and record limits; a complete test of visual layout requires the final Windows project.
- The installer expects recognizable `UniversalAnalysis.tsx` and `normalizedPdf.ts` integration anchors. If your latest customized versions differ, the dry run stops rather than rewriting the wrong code. Save the error and review the files; do not force replace.
- This archive is an installation patch, NOT a compiled Windows executable. Once verified in development, rebuild the EXE using your `desktop_packaging/build_complete_exe.py` script and test the packaged desktop on Windows.

## Rollback

Stop the frontend development server, then run from the root:

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase1_ui_patch\scripts\install_f5_ui.py "." --rollback
```

The installer backs up existing files in place and writes `.f5_phase1_ui_manifest.json`. Rollback verifies installed hashes and **refuses to overwrite any files modified after install**; do not delete the backups until you're satisfied. This rollback affects only the frontend changes of this particular patch.

## Verification performed

The packaged installer was exercised against historical `UniversalAnalysis.tsx` and `normalizedPdf.ts` fixtures from your prior project patches, including BOM/CRLF handling, dry-run, repeated install, backups, and rollback. The F5 adapter passed TypeScript type-checking in isolation and a runtime response normalization check. The React/PDF sources passed syntax checking. The complete build against the newest local user project requires running `npm run build` on your computer, since that latest source tree was not uploaded here.
