# Offline JSONL integrity verifier

Reads only the allowlisted managed files: `application.log`, `api_access.log`, `upload_audit.log`, `security_analysis.log`, `error.log` and optionally each `.1`, `.2`, `.3` rotation.

Uses bounded reads, SHA-256 per file and HMAC-SHA256 over canonical JSON of the snapshot using an external random key. Does not write to log directory, does not read arbitrary user paths inside the log directory, does not expose raw log entries, and refuses to overwrite baseline/key/report files. Checks symlinks/junctions and rejects a changing file during an offline scan. Signature verification precedes comparison.

Exit code: `0` PASS, `1` FAIL, `2` INCOMPLETE. Full instructions: `START_HERE.md` at ZIP root.

**Security boundary:** HMAC is only useful if the key and a trusted copy of the signed manifest are kept separately from any attacker who can alter the logs. This is an offline comparison—not deletion prevention or certified audit logging.
