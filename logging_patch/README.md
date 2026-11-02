# FirewallAnalyzer API 12 — Structured Audit Logging Patch

Adds local rotating JSON Lines logs **without changing the dashboard, Findings pane,
PDF report, analyzer detection rules, or returned API data**. Intended for a
locally installed API-012.0 application that includes API-011.6 hardened upload.

## Installation (Windows PowerShell)

From the project root (`...\\config analyzer`):

```powershell
# After extracting this ZIP into the project root
Test-Path .\logging_patch\scripts\install_logging.py
.\.venv-win\Scripts\python.exe .\logging_patch\scripts\install_logging.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\logging_patch\tests
.\.venv-win\Scripts\python.exe -m pytest -q
npm --prefix frontend run build
```

Restart the FastAPI server or packaged application after installing. Generate
an analysis using the existing **hardened upload endpoint**, then inspect logs:

```powershell
.\.venv-win\Scripts\python.exe .\logging_patch\scripts\check_logs.py
Get-Content .\logs\security_analysis.log -Tail 10
Get-Content .\logs\upload_audit.log -Tail 10
```

Optional development check using a sample configuration: upload through your
normal user interface; logs will be created automatically for API requests.

## Files created

- `logs/application.log` — audit logging initialization.
- `logs/api_access.log` — API method, sanitized route, status and elapsed milliseconds.
- `logs/upload_audit.log` — accepted/rejected uploads, validation result codes and sizes.
- `logs/security_analysis.log` — accepted analysis start, successful completion,
  number of structured findings (where available), and safe failure type.
- `logs/error.log` — unhandled API exceptions and 5xx responses.

Each line is a JSON object with a UTC timestamp. A log rolls over after 2 MiB,
retaining up to three older `.1`, `.2`, `.3` backup files. Some streams are
created only when a relevant event occurs. An application with no errors may
not have an `error.log` yet.

### Location

- Development from source: `<project root>\\logs\\`.
- In **PyInstaller** Windows EXE: `%LOCALAPPDATA%\\FirewallAnalyzer\\logs\\`.

The running Windows user must be able to write there. Logging failures are
reported to stderr; they do not fail an accepted configuration analysis.
For multi-process/multi-worker deployment, replace file rotation with a
centralized listener or process-safe logger.

## Privacy/security limitations

The log records never intentionally include uploaded configuration content,
file names, raw URLs/query strings, access credentials, Authorization headers,
response bodies or client IPs. Sensitive fields are denied by an allowlist.
Log files still contain operational metadata and should have OS-level access
controls and a retention/deletion policy.

**Important:** `security_analysis.log` records completion of requests made
through `/api/v1/analyze/hardened`. Older analysis endpoints are captured in
`api_access.log` but are not instrumented with detailed upload events. Consider
restricting legacy endpoints per the API-012.0 release warning.

The report PDF is generated in the React browser by jsPDF. This patch **does
not record a browser PDF download** or claim to audit PDF exports. Recording a
verified export would require a separate trusted client/server event design.
There is no functioning AI analyzer yet, so **AI inference logs are not added**.

## Rollback

```powershell
.\.venv-win\Scripts\python.exe .\logging_patch\scripts\install_logging.py "." --rollback
```

Backups and a patch manifest are stored in `.audit_logging_backup/` and
`.audit_logging_manifest.json`. Rollback refuses to overwrite later source
edits. Generated `logs/` remain intact on rollback to preserve the audit trail.
Do not rerun older API-012.0 installer or rollback scripts over modified files;
those older scripts track exact hashes of the pre-logging API files.

## Windows EXE

After installing, rebuild the React production assets (if relevant) and build
the Windows app again from its existing PyInstaller packaging commands. Because
the API main imports `app.core.audit_logging`, PyInstaller should discover it
through ordinary imports. Test the EXE at runtime and check the LocalAppData
folder. The patch is tested against representative API-011.6/012.0 source files,
not your exact current Windows checkout.
