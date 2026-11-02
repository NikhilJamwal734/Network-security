/** API-009.7: typed, narrow client for API-009.6 normalized analysis.
 * Upload contents are sent as data only; no dynamic script or HTML evaluation.
 */

export type PlatformFamily = "firewall" | "ids" | "ips";

export interface SupportedPlatform {
  platform_id: string;
  display_name: string;
  family: PlatformFamily;
  extensions: string[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type CoverageStatus = "assessed" | "not_assessed";

export interface NormalizedFinding {
  finding_id: string;
  code: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  evidence: {
    line_number: number | null;
    rule_id: string | number | null;
    related_rule_id: string | number | null;
  };
}

export interface NormalizedReport {
  rule_correlation?: RuleCorrelation;
  correlation_assurance?: CorrelationAssurance;
  object_resolution?: ObjectResolution;
  object_assurance?: ObjectAssurance;
  service_ipv6?: ServiceIPv6Review;
  nat_route_reachability?: NatRouteReachabilityReview;
  ids_deep_review?: IdsDeepReview;
  consolidation_review?: ConsolidationReview;
  correlation_accuracy_review?: CorrelationAccuracyReview;
  report_validation_review?: ReportValidationReview;
  pdf_export_review?: PdfExportReview;
  pipeline_validation_review?: PipelineValidationReview;
  input_security_review?: InputSecurityReview;
  vendor_review?: VendorReview;
  quality?: ReportQuality;
  assessment?: AdvancedAssessment;
  schema_version: "1.0";
  platform: {
    platform_id: string;
    display_name: string;
    family: PlatformFamily;
    hostname: string | null;
    detection_method: "automatic" | "explicit" | null;
  };
  summary: {
    total_findings: number;
    severity_counts: Record<Severity, number>;
    security_score: number | null;
    risk_level: string | null;
  };
  findings: NormalizedFinding[];
  coverage: {
    assessment_type: "static_configuration";
    domains: Array<{ domain: string; status: CoverageStatus }>;
    limitations: string[];
  };
  warnings: string[];
}

export const MAX_CONFIG_BYTES = 2 * 1024 * 1024;
export const SUPPORTED_FILE_EXTENSIONS = [".conf", ".cfg", ".txt", ".rules", ".yaml", ".yml"] as const;

const apiBase = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

export function filenameExtension(name: string): string {
  const lastDot = name.lastIndexOf(".");
  return lastDot === -1 ? "" : name.slice(lastDot).toLowerCase();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function readableError(detail: unknown): string {
  if (typeof detail === "string") return detail.slice(0, 400);
  if (isRecord(detail)) {
    if (typeof detail.message === "string") return detail.message.slice(0, 400);
    if (typeof detail.code === "string") return detail.code.slice(0, 100);
  }
  if (Array.isArray(detail) && detail.length) {
    const item: unknown = detail[0];
    if (isRecord(item) && typeof item.msg === "string") return item.msg.slice(0, 400);
  }
  return "The server could not process this configuration.";
}

async function parseResponse(response: Response): Promise<unknown> {
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = isRecord(body) ? body.detail : null;
    throw new Error(`HTTP ${response.status}: ${readableError(detail)}`);
  }
  return body;
}

export async function getSupportedPlatforms(signal?: AbortSignal): Promise<SupportedPlatform[]> {
  const body = await parseResponse(await fetch(`${apiBase}/api/v1/platforms`, { signal }));
  if (!isRecord(body) || !Array.isArray(body.platforms)) {
    throw new Error("The platform discovery response has an unexpected format.");
  }
  const platforms = body.platforms;
  if (!platforms.every((item: unknown) =>
    isRecord(item) && typeof item.platform_id === "string" &&
    typeof item.display_name === "string" &&
    (item.family === "firewall" || item.family === "ids" || item.family === "ips") &&
    Array.isArray(item.extensions) && item.extensions.every((x: unknown) => typeof x === "string")
  )) {
    throw new Error("The platform list contains an invalid entry.");
  }
  return platforms as SupportedPlatform[];
}

export function isNormalizedReport(body: unknown): body is NormalizedReport {
  if (!isRecord(body) || body.schema_version !== "1.0" ||
      !isRecord(body.platform) || !isRecord(body.summary) ||
      !isRecord(body.coverage) || !Array.isArray(body.findings) || !Array.isArray(body.warnings)) {
    return false;
  }
  const p = body.platform;
  const s = body.summary;
  const c = body.coverage;
  if (typeof p.platform_id !== "string" || typeof p.display_name !== "string" ||
      !["firewall", "ids", "ips"].includes(String(p.family)) ||
      (p.hostname !== null && typeof p.hostname !== "string") ||
      !["automatic", "explicit", null].includes(p.detection_method as string | null)) return false;
  if (typeof s.total_findings !== "number" || !Number.isInteger(s.total_findings) ||
      !isRecord(s.severity_counts) ||
      !["critical", "high", "medium", "low", "info", "unknown"].every(
        (key) => typeof (s.severity_counts as Record<string, unknown>)[key] === "number"
      ) || (s.security_score !== null && (typeof s.security_score !== "number" ||
        s.security_score < 0 || s.security_score > 100))) return false;
  if (!Array.isArray(c.domains) || !Array.isArray(c.limitations) ||
      !c.domains.every((d: unknown) => isRecord(d) && typeof d.domain === "string" &&
        ["assessed", "not_assessed"].includes(String(d.status))) ||
      !c.limitations.every((s: unknown) => typeof s === "string") ||
      !body.warnings.every((w: unknown) => typeof w === "string")) return false;
  return body.findings.every((f: unknown) => isRecord(f) &&
    typeof f.finding_id === "string" && typeof f.code === "string" &&
    ["critical", "high", "medium", "low", "info", "unknown"].includes(String(f.severity)) &&
    typeof f.title === "string" && typeof f.description === "string" &&
    typeof f.recommendation === "string" && isRecord(f.evidence)
  ) && s.total_findings === body.findings.length;
}

export async function analyzeNormalized(
  file: File,
  selectedPlatform: string | null,
  signal?: AbortSignal,
): Promise<NormalizedReport> {
  const params = new URLSearchParams();
  if (selectedPlatform) params.set("platform", selectedPlatform);
  const endpoint = `${apiBase}/api/v1/analyze/hardened${params.size ? `?${params.toString()}` : ""}`;
  const form = new FormData();
  form.append("file", file, file.name);
  const body = await parseResponse(await fetch(endpoint, {
    method: "POST",
    body: form,
    signal,
    // Do not set Content-Type: fetch generates the multipart boundary.
  }));
  if (!isNormalizedReport(body)) {
    throw new Error("Unexpected normalized report format from the API.");
  }
  return body;
}


export interface AdvancedAssessment {
  version: "1.0";
  scope: "uploaded_text_only";
  platform_id: string;
  review_score: {
    value: number;
    maximum: number;
    method: string;
    label: string;
    status: "provisional";
    priority: string;
    deductions: Record<Severity, number>;
    capped_for_incomplete_coverage: boolean;
    comparable_across_platforms: boolean;
    interpretation: string;
  };
  observations: Array<{
    code: string;
    title: string;
    status: "observed" | "not_visible" | "not_assessed";
    detail: string;
    evidence: { source_field: string; value: number | boolean | null; line_number: number | null };
  }>;
  coverage_review: {
    assessed_domain_count: number;
    unassessed_domain_count: number;
    unassessed_domains: string[];
    status: "partial" | "declared_checks_only";
  };
  notice: string;
}


/** Report-quality checks, not additional security findings. */
export interface ReportQuality {
  version: "1.0";
  platform_id: string;
  status: "review_needed" | "limited_coverage" | "internally_consistent";
  scope: "post_analysis_report_consistency";
  structural_checks_passed: boolean;
  finding_evidence: {
    findings_crosschecked_with_adapter: number;
    findings_total: number;
    findings_with_reported_line_references: number;
    source_text_at_line_verified: boolean;
    line_reference_note: string;
  };
  coverage: { declared_domains: number; unassessed_domains: string[]; incomplete: boolean };
  summary: { errors: number; review_items: number; observation_values_checked: number; issues_suppressed: number };
  issues: Array<{ level: "error" | "review"; code: string; explanation: string; finding_id?: string }>;
  platform_note: string;
  interpretation: string;
}


/** Supplemental checks; intentionally excluded from original risk scoring. */
export interface VendorReview {
  precision?: {
    version: string;
    status: "context_refined";
    suppressed_preliminary_checks: number;
    additional_evidence_checks: number;
    note: string;
  };
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "supplemental_vendor_specific_static_review";
  checks: Array<{
    code: string;
    severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
    title: string;
    detail: string;
    recommendation: string;
    line_number: number | null;
    rule_id: string | number | null;
  }>;
  suppressed_checks: number;
  limitations: string[];
  interpretation: string;
}


/** Opt-in, advisory correlation; outside normalized security score. */
export interface RuleCorrelation {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "static_rule_correlation_advisory";
  status: "limited" | "reviewed_subset";
  summary: {
    eligible_rules: number;
    relevant_rules_seen: number;
    rules_not_correlated: number;
    candidate_pairs: number;
    by_kind: Record<string, number>;
    truncated: boolean;
  };
  pairs: Array<{
    correlation_id: string;
    kind: string;
    confidence: "conditional" | "informational";
    title: string;
    detail: string;
    recommendation: string;
    scope: string;
    evidence: {
      line_number: number;
      related_line_number: number;
      rule_id: string;
      related_rule_id: string;
    };
  }>;
  limitations: string[];
}


/** Optional API-010.4: source-reference and ordering verification, advisory only. */
export interface CorrelationAssurance {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "correlation_evidence_and_order_advisory";
  status: "limited" | "reviewed_subset";
  summary: {
    pairs_reviewed: number;
    evidence_present: number;
    evidence_unavailable: number;
    ordering_contradictions: number;
    by_status: Record<string, number>;
    truncated: boolean;
  };
  items: Array<{
    correlation_id: string;
    status: string;
    evidence_present: boolean;
    related_line_number: number | null;
    line_number: number | null;
    explanation: string;
    next_action: string;
  }>;
  limitations: string[];
}


/** Advisory object expansion for supported ASA/FortiOS IPv4 selectors. */
export interface ObjectResolution {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "bounded_static_ipv4_object_resolution";
  status: "limited" | "reviewed_subset" | "not_assessed";
  summary: {
    definitions_seen: number;
    definitions_resolved: number;
    definitions_unresolved: number;
    rules_seen: number;
    rules_with_resolved_selectors: number;
    rules_not_resolved: number;
    candidate_pairs: number;
    truncated: boolean;
  };
  objects: Array<{
    name: string;
    kind: string;
    line_number: number;
    status: "resolved" | "unresolved";
    reason: string;
    value: string | null;
  }>;
  pairs: Array<{
    correlation_id: string;
    kind: string;
    confidence: string;
    order_status: string;
    explanation: string;
    recommendation: string;
    evidence: {
      related_line_number: number;
      line_number: number;
      related_rule_id: string;
      rule_id: string;
    };
    resolved_object_references: string[];
  }>;
  limitations: string[];
}


/** Cross-reference diagnostics scoped to the uploaded configuration (not live-device proof). */
export interface ObjectAssurance {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "uploaded_object_dependency_evidence";
  status: "limited" | "reviewed_subset" | "not_assessed";
  summary: {
    definitions_seen: number;
    references_checked: number;
    observations: number;
    missing_in_upload: number;
    cycles: number;
    repeated_definitions: number;
    incomplete: boolean;
    observations_omitted: number;
  };
  observations: Array<{
    reference: string;
    kind: string;
    status: "review_needed";
    object_name: string;
    line_number: number;
    related_line_numbers: number[];
    explanation: string;
    recommendation: string;
  }>;
  limitations: string[];
}


/** Supplemental, bounded static resolution of supported IPv6 and TCP/UDP service groups. */
export interface ServiceIPv6Review {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "static_bounded_service_group_ipv6_evidence";
  status: "reviewed_subset" | "limited" | "not_assessed";
  summary: {
    definitions_seen: number;
    definitions_resolved: number;
    definitions_unresolved: number;
    rules_seen: number;
    rules_eligible: number;
    rules_not_assessed: number;
    correlation_candidates: number;
    candidates_omitted: number;
    incomplete: boolean;
  };
  objects: Array<{
    kind: string; name: string; line_number: number;
    status: "resolved" | "unresolved"; value: string | null; reason: string;
  }>;
  pairs: Array<{
    reference: string; kind: string; confidence: string; ip_version: number;
    related_rule_id: string; rule_id: string;
    related_line_number: number; line_number: number;
    resolved_objects: string[]; order_status: string;
    explanation: string; recommendation: string;
  }>;
  limitations: string[];
}


/** Conservative upload-only NAT/static-routing evidence; not effective traffic reachability. */
export interface NatRouteReachabilityReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "static_bounded_nat_route_reachability_evidence";
  status: "reviewed_subset" | "limited" | "not_assessed";
  summary: {
    routes_seen: number; routes_resolved: number; routes_unresolved: number;
    nat_seen: number; nat_resolved: number; nat_unresolved: number;
    policies_seen: number; policies_eligible: number;
    evidence_items: number; items_omitted: number; incomplete: boolean;
  };
  evidence: Array<{
    reference: string; kind: string; line_number: number;
    policy_id: string | null; route_line_number: number | null;
    title: string; destination: string | null;
    ingress_interface: string | null; egress_interface: string | null;
    mapped_destination: string | null; confidence: string;
    explanation: string; recommendation: string;
  }>;
  limitations: string[];
}


/** Static configuration evidence; never infers effective sensor protection. */
export interface IdsDeepReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "bounded_static_ids_configuration_evidence";
  status: "reviewed_subset" | "limited" | "not_applicable";
  summary: {
    rules_inspected: number; duplicate_rule_ids: number; external_references: number;
    outputs_explicitly_enabled: number; outputs_explicitly_disabled: number; outputs_declared: number;
    interfaces_declared: number; evidence_items: number; items_omitted: number;
    incomplete: boolean;
  };
  evidence: Array<{
    reference: string; kind: string; line_number: number; title: string;
    setting: string; observation: string; implication: string;
    recommendation: string; confidence: string;
  }>;
  limitations: string[];
}


/** Advisory consolidation of one normalized upload: no findings or score changes. */
export interface ConsolidationReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "cross_review_evidence_consistency_single_upload";
  status: "reviewed_subset" | "limited";
  summary: {
    sections_present: number; sections_unavailable: number;
    advisory_items_examined: number; candidate_links: number;
    quality_observations: number; limited_sections: number;
    items_omitted: number; incomplete: boolean;
  };
  sections: Array<{
    name: string; availability: string; status: string;
    items_examined: number; items_omitted: number; applicable: boolean;
  }>;
  issues: Array<{
    reference: string; kind: string; section: string;
    source_line: number | null; observation: string;
    recommendation: string; confidence: string;
  }>;
  links: Array<{
    reference: string; kind: string; source_line: number;
    signal: string; title: string;
    related: Array<{section: string; locator: string; reference: string; source_line: number}>;
    reason: string; recommendation: string; confidence: string;
  }>;
  limitations: string[];
}


/** Advisory correlation accuracy for one configuration; not an FP rate or remediation engine. */
export interface CorrelationAccuracyReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "single_upload_advisory_link_validation";
  status: "reviewed_subset" | "limited";
  summary: {
    links_checked: number; plausible_links: number; unsupported_links: number;
    uncertain_links: number; finding_metadata_pairs: number;
    severity_conflicts: number; findings_without_line: number;
    items_omitted: number; incomplete: boolean;
  };
  decisions: Array<{
    reference: string; upstream_reference: string; source_line: number | null;
    classification: string; reason: string; recommended_action: string;
    confidence: string;
  }>;
  quality_observations: Array<{
    reference: string; kind: string; source_line: number | null;
    reason: string; recommendation: string; confidence: string;
  }>;
  limitations: string[];
}


/** Static report-contract preflight; does not certify PDF render or security. */
export interface ReportValidationReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "single_upload_report_contract_preflight";
  status: "consistent_subset" | "limited" | "inconsistent";
  summary: {
    checks_performed: number; passed_checks: number; discrepancies: number;
    warnings: number; reviews_examined: number; items_omitted: number;
    incomplete: boolean;
  };
  checks: Array<{
    reference: string; section: string; check: string; result: string;
    observed: string; expected: string; explanation: string;
    recommended_action: string; confidence: string;
  }>;
  limitations: string[];
}


/** Static PDF readiness preflight; actual PDF bytes are checked in the browser on export. */
export interface PdfExportReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "static_single_upload_pdf_export_preflight";
  status: "preflight_pass" | "limited" | "blocked";
  summary: { checks: number; passed: number; warnings: number; blockers: number; omitted: number };
  observations: Array<{
    reference: string; kind: string; result: string;
    observation: string; recommendation: string;
  }>;
  limitations: string[];
}


/** API-011.4 server-side integration checks; browser export must be verified separately. */
export interface PipelineValidationReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "single_upload_server_response_contract_and_manual_export_checklist";
  status: "server_checks_passed" | "limited" | "blocked";
  summary: { checks: number; passed: number; warnings: number; blockers: number; manual_required: number };
  stages: Array<{
    reference: string; stage: string; result: "pass" | "warning" | "blocker" | "manual_required";
    observation: string; recommendation: string; evidence_basis: string;
  }>;
  limitations: string[];
}

/** API-011.6: accepted input checks, not a general security guarantee. */
export interface InputSecurityReview {
  version: "1.0";
  status: "accepted";
  scope: "single_file_text_input_precheck";
  summary: { byte_count: number; line_count: number; checks_passed: number };
  sha256: string;
  checks: Array<{ name: string; result: "pass" }>;
  limitations: string[];
}
