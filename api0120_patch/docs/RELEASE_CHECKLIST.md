# API-012.0 — Final release verification

## Scope

This is an **additive final release gate**, not a claim that the analyzer has
passed a production security assessment. It is built for an on-premises or
isolated-network deployment. The existing Cisco ASA, FortiOS, Snort and
Suricata analysis paths, Findings page, dashboard headings, PDF evidence and
scores are not modified.

The endpoint `GET /api/v1/release/status` returns the installed release
number and clearly states `production_ready: false`. It intentionally avoids
returning hostpaths, dependency inventories, environment secrets, request data
or internal stack traces.

## Operator verification checklist

- [ ] Existing API-011.6 hardening patch installed; previous tests pass.
- [ ] API-012.0 patch tests pass in the Windows project environment.
- [ ] Full backend pytest suite passes with previous Windows test-ID fix.
- [ ] Production TypeScript/Vite build passes (`npm run build`).
- [ ] Backend is running on a loopback or otherwise approved private bind.
- [ ] A representative firewall or IDS configuration uploads successfully
      through `/api/v1/analyze/hardened`, with correct platform parsing,
      expected findings, and accepted-input review.
- [ ] Browser generates and downloads a non-empty report for each supported
      platform; independently inspect page layout for truncation and clipping.
- [ ] A saved sample PDF passes the optional `pypdf` parsing/extractable-text
      check, and is visually reviewed separately.
- [ ] Older upload endpoints are protected or disabled to prevent bypass of
      newer file validation.
- [ ] Authentication and authorization (or equivalent network restriction)
      are applied to uploads, saved results, and any exposed reports.
- [ ] Reverse-proxy body-size and timeout limits are enforced **before**
      multipart processing. Consider rate limiting as appropriate.
- [ ] Host is not accidentally exposed on a public interface; cross-origin
      policy is restricted to trusted origins.
- [ ] Operator confirms least-privilege runtime, isolated data storage,
      file retention rules, logs without raw secrets, and recoverable backups.
- [ ] Dependency audits and offline install artifacts have been reviewed.
- [ ] Performance/load and large configuration benchmarks have been recorded;
      API-011.5 was skipped and is NOT implicitly fulfilled.

## What is measured by the local release gate

- Presence and consistency of the final backend/frontend component paths.
- Router registration exactly once, preserving the hardened upload flow.
- Optionally: complete pytest suite, `npm run build`, saved PDF parse/text,
  and real HTTP upload on **localhost only**.
- JSON summary with `failed`, `not_run`, and `deployment_warnings`.

*The local gate cannot verify external deployment controls, threat-model
correctness, PDF appearance, completeness of all security findings, or
accuracy of risk scoring.* It **never** sets `production_ready` to true.

## API-011.5 status

This final integration stage is compatible with API-011.6 without installing
API-011.5. It does not fill the gap in performance testing. Recommended future
work: multi-megabyte configurations, parser timeouts, CPU/memory measurement,
front-end large finding-set rendering, and repeated PDF export load tests.

## Rollback

The rollback command validates that installed files still match their
post-install hashes. If anyone edits those files later, rollback refuses to
overwrite those edits. The manifest and backups live under the project root.
