# Final Windows acceptance

Automated runner checks: EXE hash matches build receipt; fresh dynamic loopback server; dashboard HTML; Health endpoint; invalid Host (400) and Origin (403); F5 with and without JSON; Cisco ASA, FortiOS, Snort, Suricata; JSON Logs page/API and on-disk JSONL activity; controlled shutdown. See `check_exe.py`.

Manual steps that cannot be certified by the runner:
- Open React UI, verify the professional F5 selection label is installed, navigate Dashboard/Findings/Reports and check layout.
- Generate PDFs for all five platforms, including F5 with/without evidence. Check F5 evidence assurance text in a new PDF and confirm no unsupported runtime security claims.
- Open JSON Logs viewer, verify severity colors, correct event data and accessibility. No sensitive configuration content should appear in logs.
- Close the standalone EXE and confirm no orphaned Uvicorn process/port.
- Test on a clean Windows VM with no source tree, Node, Python or development dependencies installed.
- Confirm signed baseline/key storage and relevant Windows ACLs separately; the integrity snapshot cannot prevent admin deletion or prove completeness of all log streams.
- Re-run release gate after each source change; keep unresolved historical test failures documented.

Record the date, operator, tested EXE SHA-256, `release_final_gate.json`, `release_final_build_result.json`, and `recommendations_123_exe_acceptance.json`. Do not claim deployment or production-security certification from synthetic results.
