/** F5 Phase 1 adapter. API-012 vendor registry is unchanged; explicit F5 uploads
 * use the already installed, independently tested endpoint.
 * No new analysis or severity decisions are made by this UI adapter.
 */
import type { NormalizedReport, NormalizedFinding, SupportedPlatform, Severity } from "./universal";

export const F5_PLATFORM_ID = "f5_bigip";

export const F5_PLATFORM: SupportedPlatform = {
  platform_id: F5_PLATFORM_ID,
  display_name: "F5 BIG-IP (Phases 1 + 2)",
  family: "firewall",
  extensions: [".conf", ".cfg", ".txt"],
};

export function withF5Platform(items: SupportedPlatform[]): SupportedPlatform[] {
  return items.some((p) => p.platform_id === F5_PLATFORM_ID)
    ? items
    : [...items, F5_PLATFORM];
}

export interface F5EvidenceItem {
  code: string;
  title: string;
  severity: string;
  confidence: string;
  affected_object: string;
  object_type: string;
  line_number: number | null;
  associated_virtual_servers: string[];
  evidence: { setting: string; observed: string; line_number: number | null };
  description: string;
  recommendation: string;
  limitations: string;
}

export interface F5Phase1Review {
  findings: F5EvidenceItem[];
  review_observations: F5EvidenceItem[];
  total_profiles: number;
  total_virtual_servers: number;
  limitations: string[];
}

export type F5NormalizedReport = NormalizedReport & { f5_phase1_review: F5Phase1Review };

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function nonNegativeInt(x: unknown): number {
  return typeof x === "number" && Number.isSafeInteger(x) && x >= 0 ? x : 0;
}

function parseEvidence(value: unknown): F5EvidenceItem {
  if (!isObject(value) || !isObject(value.evidence) ||
      typeof value.code !== "string" || !/^F5-\d{3}$/.test(value.code) ||
      typeof value.title !== "string" || typeof value.severity !== "string" ||
      typeof value.description !== "string" ||
      typeof value.recommendation !== "string" ||
      typeof value.affected_object !== "string" ||
      typeof value.object_type !== "string") {
    throw new Error("Unexpected F5 finding format from the backend.");
  }
  const source = value.evidence;
  const sourceLine = nonNegativeInt(source.line_number) || null;
  return {
    code: value.code,
    title: value.title,
    severity: value.severity,
    confidence: typeof value.confidence === "string" ? value.confidence : "unspecified",
    affected_object: value.affected_object,
    object_type: value.object_type,
    line_number: nonNegativeInt(value.line_number) || sourceLine,
    associated_virtual_servers: Array.isArray(value.associated_virtual_servers)
      ? value.associated_virtual_servers.filter((v): v is string => typeof v === "string").slice(0, 100)
      : [],
    evidence: {
      setting: typeof source.setting === "string" ? source.setting : "",
      observed: typeof source.observed === "string" ? source.observed : "",
      line_number: sourceLine,
    },
    description: value.description,
    recommendation: value.recommendation,
    limitations: typeof value.limitations === "string" ? value.limitations : "Static configuration subset only.",
  };
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];
function findingToNormalized(item: F5EvidenceItem, position: number): NormalizedFinding {
  const severity = item.severity.toLowerCase();
  if (!SEVERITIES.includes(severity as Severity)) {
    throw new Error("Unexpected F5 finding severity.");
  }
  return {
    finding_id: `f5-phase1:${item.code}:${item.line_number ?? 0}:${position}`,
    code: item.code,
    severity: severity as Severity,
    title: item.title,
    description: `${item.description} Affected object: ${item.affected_object}; ` +
      `setting: ${item.evidence.setting}; observed: ${item.evidence.observed}.`,
    recommendation: item.recommendation,
    evidence: {
      line_number: item.line_number,
      rule_id: item.affected_object,
      related_rule_id: null,
    },
  };
}

/** Converts the standalone Phase 1 endpoint into the existing dashboard/PDF contract.
 * Advisory observations remain separate: they are NOT added to findings or score.
 */
export function normalizeF5Phase1(body: unknown): F5NormalizedReport {
  if (!isObject(body) || !isObject(body.platform) ||
      body.platform.platform_id !== F5_PLATFORM_ID ||
      !isObject(body.summary) || !Array.isArray(body.findings) ||
      !Array.isArray(body.review_observations) || !isObject(body.coverage) ||
      !Array.isArray(body.coverage.limitations)) {
    throw new Error("Unexpected F5 Phase 1 response. Check that the F5 backend addon is installed.");
  }
  if (body.findings.length > 1500 || body.review_observations.length > 1500 ||
      body.summary.total_findings !== body.findings.length ||
      body.summary.total_review_observations !== body.review_observations.length) {
    throw new Error("F5 response counts or evidence bounds are inconsistent.");
  }
  const findings = body.findings.map(parseEvidence);
  const observations = body.review_observations.map(parseEvidence);
  const normalized = findings.map(findingToNormalized);
  const severityCounts = Object.fromEntries(
    SEVERITIES.map((severity) => [severity, normalized.filter((item) => item.severity === severity).length]),
  ) as Record<Severity, number>;
  const limitations = body.coverage.limitations.filter((v): v is string => typeof v === "string");
  // Phase 2 evidence remains operator-supplied, not independently verified.
  const phase2: Record<string, unknown> = isObject(body.f5_phase2_review) ? body.f5_phase2_review : {};
  const hasUcsEvidence = phase2.ucs_evidence_supplied === true ||
    [...findings, ...observations].some((item) => item.code === "F5-005" && item.confidence !== "not_assessed");
  const hasSignatureEvidence = phase2.signature_update_evidence_supplied === true ||
    [...findings, ...observations].some((item) => item.code === "F5-006" && item.confidence !== "not_assessed");
  return {
    schema_version: "1.0",
    platform: {
      platform_id: F5_PLATFORM_ID,
      display_name: "F5 BIG-IP LTM / Advanced WAF (Phases 1 + 2)",
      family: "firewall",
      hostname: null,
      detection_method: "explicit",
    },
    summary: {
      total_findings: normalized.length,
      severity_counts: severityCounts,
      security_score: null,
      risk_level: "NOT_SCORED",
    },
    findings: normalized,
    coverage: {
      assessment_type: "static_configuration",
      domains: [
        { domain: "F5 TLS / cipher / certificate / HSTS Phase 1 subset", status: "assessed" },
        { domain: "F5 Phase 2 - virtual logging association and iRule inventory subset", status: "assessed" },
        { domain: "F5 UCS backup evidence (operator assertion only)", status: hasUcsEvidence ? "assessed" : "not_assessed" },
        { domain: "F5 WAF signature update evidence (operator assertion only)", status: hasSignatureEvidence ? "assessed" : "not_assessed" },
        { domain: "Other F5 BIG-IP, LTM and WAF settings", status: "not_assessed" },
      ],
      limitations: [
        ...limitations,
        "F5 Phases 1 and 2 use a separate endpoint; other vendor pipelines do not assess this configuration.",
        "Review observations are not confirmed vulnerabilities and are excluded from finding totals.",
        "Security score is deliberately not assigned.",
      ],
    },
    warnings: [],
    f5_phase1_review: {
      findings,
      review_observations: observations,
      total_profiles: nonNegativeInt(body.summary.total_profiles),
      total_virtual_servers: nonNegativeInt(body.summary.total_virtual_servers),
      limitations,
    },
    // Validated upload provenance from the already installed F5 endpoint.
    ...(isObject(body.input_security_review) ? { input_security_review: body.input_security_review } : {}),
  } as F5NormalizedReport;
}

function baseUrl(): string {
  // Dev server serves React on 5173 and API on 8000; desktop serves both
  // on a random loopback port. Do not hardcode 8000 in a packaged executable.
  return (import.meta.env.DEV
    ? (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000")
    : window.location.origin).replace(/\/+$/, "");
}

/** Optional F5 Phase 2 operator assertions. This is metadata, not a UCS archive.
 * Checks are for user feedback only. The FastAPI backend validates again.
 */
const F5_EVIDENCE_MAX_BYTES = 16_384;
const F5_UPDATE_STATUSES = ["current", "unknown", "failed", "disabled", "manual", "scheduled", "outdated"];

function isF5Record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCalendarDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(value + "T00:00:00Z");
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

async function readF5OperatorEvidence(file: File, signal?: AbortSignal): Promise<string> {
  if (!/\.json$/i.test(file.name) || file.size === 0 || file.size > F5_EVIDENCE_MAX_BYTES) {
    throw new Error("F5 evidence must be a nonempty .json file of at most 16 KiB.");
  }
  const raw = (await file.text()).replace(/^\uFEFF/, "");
  if (signal?.aborted) throw new Error("F5 evidence read cancelled.");
  let value: unknown;
  try { value = JSON.parse(raw); }
  catch { throw new Error("F5 evidence is not valid JSON."); }
  if (!isF5Record(value) || Object.keys(value).some((k) => k !== "ucs_backups" && k !== "signature_updates")) {
    throw new Error("F5 evidence accepts only ucs_backups and signature_updates fields.");
  }
  if ("ucs_backups" in value) {
    const backups = value.ucs_backups;
    if (!Array.isArray(backups) || backups.length > 30 || backups.some((entry: unknown) => {
      if (!isF5Record(entry) || Object.keys(entry).length !== 2 ||
          typeof entry.name !== "string" || typeof entry.encrypted !== "boolean") return true;
      const name = entry.name;
      return name.length > 128 || !/^[a-zA-Z0-9_.\/-]+$/.test(name) ||
        name.includes("\\") || name.split("/").includes("..");
    })) throw new Error("F5 UCS evidence needs up to 30 safe {name, encrypted} entries.");
  }
  if ("signature_updates" in value) {
    const update = value.signature_updates;
    if (!isF5Record(update) || Object.keys(update).length !== 2 ||
        typeof update.status !== "string" || !F5_UPDATE_STATUSES.includes(update.status) ||
        !(update.last_installed === null ||
          (typeof update.last_installed === "string" && isCalendarDate(update.last_installed)))) {
      throw new Error("F5 signature_updates requires a supported status and last_installed date or null.");
    }
  }
  const compact = JSON.stringify(value);
  if (new TextEncoder().encode(compact).length > F5_EVIDENCE_MAX_BYTES) {
    throw new Error("F5 evidence exceeds 16 KiB after normalization.");
  }
  return compact;
}

export async function analyzeF5Phase1(file: File, signal?: AbortSignal, operatorEvidence?: File | null): Promise<F5NormalizedReport> {
  const form = new FormData();
  form.append("file", file, file.name);
  if (operatorEvidence) {
    form.append("evidence_json", await readF5OperatorEvidence(operatorEvidence, signal));
  }
  if (signal?.aborted) throw new Error("F5 upload cancelled.");
  const response = await fetch(`${baseUrl()}/api/v1/analyze/f5/phase1`, {
    method: "POST", body: form, signal,
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = isObject(body) ? body.detail : null;
    const message = isObject(detail) && typeof detail.message === "string"
      ? detail.message : typeof detail === "string" ? detail : "F5 configuration analysis failed.";
    throw new Error(`HTTP ${response.status}: ${message.slice(0, 300)}`);
  }
  return normalizeF5Phase1(body);
}
