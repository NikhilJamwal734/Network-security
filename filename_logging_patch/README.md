# API 12 filename audit upgrade

This small, reversible patch adds **safe uploaded file basenames** to the existing
API 12 `upload_audit.log` and `security_analysis.log` event records.

It does not log full filesystem paths, configuration contents, raw URLs,
client IPs, request bodies, or credentials. It changes no analysis logic, scores,
PDF reports, dashboard components, or API responses.

## Prerequisites

- API-012.0 and the `FirewallAnalyzer-API12-Structured-Logging-Patch` installed
- Python environment used for your existing backend, e.g. `.venv-win`

## Install (PowerShell, from project root)

```powershell
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-Logging-Filename-Upgrade.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\filename_logging_patch\scripts\install_filename_logging.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\filename_logging_patch\tests
```

Restart the backend, upload a *new* configuration through the hardened endpoint,
and inspect the new JSONL entries:

```powershell
Get-Content .\logs\upload_audit.log -Tail 10
Get-Content .\logs\security_analysis.log -Tail 10
```

Expected example entry (sample, not a real log):

```json
{"timestamp_utc":"2026-10-26T11:30:00.000+00:00","event":"upload_accepted","filename":"ASA-FIREWALL.cfg","platform":"cisco_asa","size_bytes":1024}
```

Only filenames consisting of 1–120 ASCII letters, numbers, spaces, dots,
underscores, and hyphens are logged. Paths, control characters, invalid names,
Unicode names, and unusually long names are omitted to avoid unsafe logs.
The filename itself may reveal sensitive information, so protect access to log files.

**Important:** The original logging patch keeps a checksum manifest. This upgrade
alters two of its installed files, so first run **this upgrade's** rollback before
running the original logging patch's rollback.

## Rollback

```powershell
.\.venv-win\Scripts\python.exe .\filename_logging_patch\scripts\install_filename_logging.py "." --rollback
```

Rebuild your EXE after testing the updated backend to include these changes.
