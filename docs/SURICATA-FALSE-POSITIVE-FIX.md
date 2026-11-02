# Suricata parser accuracy: comment handling

## Reproduced defect

The PDF produced by the previous analyzer reported 7 x `SURICATA-008` Medium findings. Each source line in the user's Suricata 8.0 YAML was a documentation comment beginning with `# Log ...`. The parser stripped `#`, saw the action keyword `log`, attempted to parse the remaining English prose as a Suricata detection rule, and reported failure.

Affected lines: 191, 194, 197, 547, 560, 1049, 1851.

## Corrected handling

1. Blank and YAML directive lines are skipped as before.
2. Lines whose first non-space character is `#` are ignored unless the remainder matches a complete Suricata detection-rule header. Valid commented rules remain represented as disabled rules. Invalid commented snippets are not active security violations.
3. Active lines enter the rule parser only if they begin with an action keyword followed by a recognized protocol. Active lines which meet that test but cannot parse are still recorded as malformed for `SURICATA-008`.
4. Other YAML lines continue through the API-009.5 limited YAML text parser without YAML deserialization.

## Safety and limitations

- The uploaded configuration remains untrusted text. Nothing is executed or sent to Suricata.
- The parser does not follow `rule-files` references, open rule contents, or analyze packet traffic.
- The supported header and YAML subset remains limited; a successful partial parse is NOT equivalent to validation by Suricata itself.
- Security score remains unassigned for Suricata.
- PDF files previously generated must be re-created after the patched backend analyzes the original file again.

## Verification

Against the full user-provided YAML in the compatibility environment:
- Before patch: 7 malformed rule-like lines at the line numbers listed above.
- After patch: 0 malformed rule-like lines, 0 findings from the available rule checks, 2 referenced rule-file entries, EVE enabled, HOME_NET present.
- Both `POST /api/v1/analyze/universal` and `POST /api/v1/analyze/normalized` returned HTTP 200 with 0 findings after patch.
- 15 new targeted regression tests passed.
- 149 combined targeted + API-009.5 + API-009.6 tests passed.
- 4 pre-existing ASA-specific tests cannot pass in the isolated compatibility workspace because its ASA implementation and `configs/firewall.conf` are incomplete/missing; user should run the full suite on the actual project.
