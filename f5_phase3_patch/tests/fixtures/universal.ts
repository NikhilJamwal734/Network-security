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
  const endpoint = `${apiBase}/api/v1/analyze/normalized${params.size ? `?${params.toString()}` : ""}`;
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
