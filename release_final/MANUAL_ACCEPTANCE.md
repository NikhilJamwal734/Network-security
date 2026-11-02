# Manual release acceptance — packaged Windows EXE

The automated release gate does not replace these checks. Run them on the **newly packaged EXE**, preferably on a separate Windows test system without development dependencies.

- [ ] EXE launches without Python, Node or source checkout; dashboard loads from its announced dynamic loopback URL.
- [ ] Dashboard and Findings display correctly; no duplicate findings on dashboard, no deleted panels reappeared, navigation works on desktop and mobile width.
- [ ] F5 upload with `f5_phase2_sample.conf` **alone** produces 3 findings, 5 review observations and a downloadable readable PDF.
- [ ] F5 upload with `.conf` and **optional** `f5_phase3_evidence.json` produces 4 findings, 4 observations; F5-005 tagged `operator_supplied_unverified`, F5-006 `failed` in review; PDF coverage says operator evidence assessed.
- [ ] Confirm evidence-first configuration-selection order no longer loses selected JSON; replacing a previously selected config clears earlier evidence intentionally.
- [ ] Cisco ASA, FortiOS, Snort and Suricata each accept a known-good synthetic configuration; platform identifiers, accurate findings and vendor PDF sections are maintained. Compare with a saved pre-F5 baseline where possible.
- [ ] F5 malformed metadata returns a helpful error without crash; binary configuration is rejected; oversized files and invalid encodings are rejected.
- [ ] Logs viewer renders existing JSON records and severity colors; API `/api/v1/logs` remains loopback-only; log filenames and event fields remain visible.
- [ ] Report/PDF opens, page numbering and long-text pagination are correct; no clipped text. Findings, summary totals, source lines and SHA-256 agree. Avoid pasting sensitive configs into logs or reports.
- [ ] EXE shutdown stops the local backend. Re-launch does not leave orphaned ports or expose the app to non-loopback interfaces.
- [ ] Inspect AV status, endpoint permissions, audit-log file access control, package dependency versions, distribution signing and installer provenance before external release.
- [ ] Confirm the release build SHA-256, the tested archive/EXE version, and backup/rollback procedure are recorded in release notes.

**If any of these fail, the release is NOT accepted** even if automated checks show PASS. Do not interpret operator-provided evidence as independently validated device state.
