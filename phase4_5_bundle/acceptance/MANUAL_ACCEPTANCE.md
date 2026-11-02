# Final packaged EXE acceptance checklist

The automated script does **not** perform a browser render, PDF print, or a real clean-machine deployment. Complete and record these separately **after** the script succeeds.

| Item | Required manual action | Result |
|---|---|---|
| Dashboard UI | Launch `desktop_release_single/FirewallAnalyzer.exe` normally; confirm the Dashboard and navigation render, buttons work, and no console errors appear | PENDING |
| Cisco ASA UI | Select Cisco ASA; upload `release_final/examples/cisco_asa.conf`; confirm findings and export a PDF | PENDING |
| FortiOS UI | Select FortiOS; upload `release_final/examples/fortios.conf`; confirm findings and export a PDF | PENDING |
| Snort UI | Select Snort; upload `release_final/examples/snort.conf`; confirm the analysis and PDF | PENDING |
| Suricata UI | Select Suricata; upload `release_final/examples/suricata.yaml`; confirm the analysis and PDF | PENDING |
| JSON Logs viewer | Open the **actual port** shown by the EXE at `/logs.html`; verify records load, severity colours, filenames and timestamps; verify no uploaded raw configuration appears | PENDING |
| Graceful Ctrl+C | In the original terminal running the EXE, press Ctrl+C; confirm the process exits and the announced browser URL stops responding. If the script reports INCOMPLETE for CTRL_BREAK, this manual check is essential | PENDING |
| SHA-256 | Run `Get-FileHash .\desktop_release_single\FirewallAnalyzer.exe -Algorithm SHA256`; compare to `release_final_build_result.json` field `exe_sha256` | PENDING |
| Clean VM | Copy the EXE to a clean Windows VM and verify operation without project source, Python, or Node.js | PENDING |

**Release decision:** Record the automated JSON result and complete every manual check. If any item fails, distribution is not approved. Historical patch-test warning (19 failures/5 errors in older fixtures) must remain documented.
