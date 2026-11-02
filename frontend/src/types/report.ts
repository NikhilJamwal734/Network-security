/**
 * TypeScript types for the firewall analyzer report.
 *
 * Source of truth: `reports/firewall_report.json`, produced by
 * `app/reporting/report.py` (`SecurityReport.to_dict`) and
 * `app/main.py` (which adds the `source` key).
 *
 * IMPORTANT: The current report schema only exposes AGGREGATE COUNTS
 * for rules, network objects, services, NAT rules and routes (inside
 * `summary`). It does NOT include per-object arrays (no list of the
 * actual rules, network objects, services, NAT rules, or routes) and
 * findings do not embed the full rule they refer to, only its
 * `rule_id` / `line_number`. Nothing below invents fields that aren't
 * present in the JSON — where the backend only provides a count, the
 * type below only provides a count.
 */

// ---------------------------------------------------------------------------
// Severity / risk level
// ---------------------------------------------------------------------------

/** Severity level used for individual findings. */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

/**
 * Overall risk classification for the whole report. Currently uses the
 * same four values as `Severity` (see `ReportGenerator._calculate_risk_level`
 * in app/reporting/report.py), kept as a distinct alias in case the two
 * diverge in the future.
 */
export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

// ---------------------------------------------------------------------------
// Security score
// ---------------------------------------------------------------------------

/**
 * The overall security-health score and the risk level derived from it.
 * This is a heuristic score (0-100), not a compliance score or formal
 * risk assessment.
 */
export interface SecurityScore {
  security_score: number;
  risk_level: RiskLevel;
}

// ---------------------------------------------------------------------------
// Rule information (as referenced from a finding)
// ---------------------------------------------------------------------------

/**
 * Identifies which rule a finding is about: the rule's ID and the line
 * number it appears on in the source configuration file. Both may be
 * `null` for findings that aren't tied to a specific ACL rule (e.g.
 * unused network/service object findings, which instead point at the
 * line where the object is defined via `line_number`).
 */
export interface RuleInformation {
  rule_id: number | null;
  line_number: number | null;
}

/**
 * Identifies a second, related rule referenced by a finding — for
 * example, the earlier rule that shadows, duplicates, or is matched by
 * a NAT translation. `null` when the finding does not reference
 * another rule.
 */
export interface RelatedRuleInformation {
  related_rule_id: number | null;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/** A single security finding produced by the analyzer. */
export interface Finding extends RuleInformation, RelatedRuleInformation {
  severity: Severity;
  /** Finding code, e.g. "FW-001". */
  code: string;
  title: string;
  description: string;
  recommendation: string;
}

// ---------------------------------------------------------------------------
// Configuration object counts (network objects, services, NAT rules, routes)
// ---------------------------------------------------------------------------
// The report does not include arrays of the actual network objects,
// service objects, NAT rules, or routes — only totals, as part of the
// configuration summary below. These aliases exist so other frontend
// code can refer to "how many rules / network objects / ..." by a
// semantically named type instead of reaching into `ConfigurationSummary`
// directly, without duplicating or inventing any fields.

export type RuleCount = ConfigurationSummary["total_rules"];
export type NetworkObjectCount = ConfigurationSummary["total_network_objects"];
export type ServiceObjectCount = ConfigurationSummary["total_service_objects"];
export type NatRuleCount = ConfigurationSummary["total_nat_rules"];
export type RouteCount = ConfigurationSummary["total_routes"];

// ---------------------------------------------------------------------------
// Configuration summary
// ---------------------------------------------------------------------------

/**
 * High-level summary of the firewall configuration and the findings
 * generated against it. Mirrors `ReportSummary` in
 * app/reporting/report.py exactly.
 */
export interface ConfigurationSummary extends SecurityScore {
  total_rules: number;
  total_network_objects: number;
  total_service_objects: number;
  total_nat_rules: number;
  total_routes: number;

  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
}

// ---------------------------------------------------------------------------
// Source / warnings
// ---------------------------------------------------------------------------

/** Where the analyzed configuration came from. Added by app/main.py. */
export interface ReportSource {
  configuration_file: string;
}

/** Free-form warning strings emitted while parsing/analyzing the config. */
export type Warning = string;

// ---------------------------------------------------------------------------
// Top-level report
// ---------------------------------------------------------------------------

/** The full shape of reports/firewall_report.json. */
export interface FirewallReport {
  vendor: string;
  hostname: string;
  summary: ConfigurationSummary;
  findings: Finding[];
  warnings: Warning[];
  source: ReportSource;
}