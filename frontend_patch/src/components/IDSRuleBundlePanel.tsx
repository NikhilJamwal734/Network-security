import { useEffect, useState, type ChangeEvent } from "react";
import "./IDSRuleBundlePanel.css";

interface BundleFinding {
  code: string;
  severity: string;
  title: string;
  description: string;
  recommendation: string;
  evidence: {
    filename: string;
    line_number: number | null;
    sid?: number | null;
    related_filename?: string;
    related_line_number?: number;
  };
}
interface BundleResult {
  platform: { platform_id: string };
  summary: {
    total_findings: number;
    rule_files_uploaded: number;
    enabled_rules_visible: number;
    security_score: null;
  };
  findings: BundleFinding[];
  coverage: {
    referenced_files: {
      entries_visible: number;
      filename_candidate_matches: number;
      not_uploaded: number;
      identity_verified: false;
    };
    effective_loaded_rules: string;
  };
  warnings: string[];
  notice: string;
}

const MAX_EACH = 2 * 1024 * 1024;
const MAX_COMBINED = 4 * 1024 * 1024;
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

function messageFromError(body: unknown): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail.slice(0, 260);
    if (detail && typeof detail === "object" && "message" in detail) {
      return String((detail as { message: unknown }).message).slice(0, 260);
    }
  }
  return "Could not analyze the selected IDS rule files.";
}

interface Props {
  platformId: string;
  configurationFile?: File | null;
}

/** Opt-in rule review; results are separate from the original normalized score. */
export default function IDSRuleBundlePanel({ platformId, configurationFile = null }: Props) {
  const [files, setFiles] = useState<File[]>([]);
  const [result, setResult] = useState<BundleResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const eligible = platformId === "snort" || platformId === "suricata";

  useEffect(() => {
    setResult(null);
    setFiles([]);
    setError(null);
  }, [platformId, configurationFile]);

  if (!eligible) return null;

  function handleFiles(event: ChangeEvent<HTMLInputElement>) {
    setFiles(Array.from(event.target.files || []));
    setResult(null);
    setError(null);
  }

  async function submit() {
    if (busy || !eligible || files.length === 0) return;
    const form = new FormData();
    for (const file of files) form.append("rules", file, file.name);
    // This file is supplied by the user. It is never inferred from a rule-file path.
    if (configurationFile && !configurationFile.name.toLowerCase().endsWith(".rules")) {
      form.append("config", configurationFile, configurationFile.name);
    }
    setError(null);
    setResult(null);
    setBusy(true);
    try {
      const response = await fetch(`${API_BASE}/api/v1/analyze/ids-bundle?platform=${encodeURIComponent(platformId)}`, {
        method: "POST", body: form,
      });
      const data: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(messageFromError(data));
      if (!data || typeof data !== "object" || !("summary" in data) || !("findings" in data)) {
        throw new Error("Unexpected IDS bundle response format.");
      }
      const checked = data as BundleResult;
      if (!Array.isArray(checked.findings) || typeof checked.summary?.total_findings !== "number") {
        throw new Error("Invalid IDS bundle response.");
      }
      setResult(checked);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Rule inspection failed.");
    } finally {
      setBusy(false);
    }
  }

  const validFiles = files.length >= 1 && files.length <= 8 &&
    files.every((f) => f.name.toLowerCase().endsWith(".rules") && f.size > 0 && f.size <= MAX_EACH) &&
    files.reduce((total, f) => total + f.size, configurationFile?.name.toLowerCase().endsWith(".rules") ? 0 : (configurationFile?.size || 0)) <= MAX_COMBINED;

  return (
    <section className="ids-bundle-panel ua-panel" aria-labelledby="ids-bundle-title">
      <div className="ids-bundle-heading">
        <div>
          <p className="ua-eyebrow">OPTIONAL · API-009.9</p>
          <h2 id="ids-bundle-title">Inspect additional {platformId === "snort" ? "Snort" : "Suricata"} rules</h2>
          <p>Attach rule files explicitly to check duplicate identifiers and supported rule syntax across files.</p>
        </div>
        <span className="ids-bundle-label">Static text review</span>
      </div>
      <label className="ids-bundle-picker">
        <span>Select up to 8 rule files (.rules, 2 MiB each; 4 MiB combined)</span>
        <input type="file" accept=".rules" multiple onChange={handleFiles} disabled={busy} />
      </label>
      <p className="ids-bundle-note">Referenced paths in YAML or Snort include directives are never opened. An uploaded filename match does not prove the rule is deployed.</p>
      {!!files.length && <p className="ids-bundle-note">Selected: {files.map((f) => f.name).join(", ")}</p>}
      {!!files.length && !validFiles && <p role="alert" className="ids-bundle-error">Check the file count, .rules extensions, and upload size limits.</p>}
      <button type="button" className="ua-primary" disabled={!validFiles || busy} onClick={() => { void submit(); }}>
        {busy ? "Inspecting uploaded rules…" : "Inspect uploaded rule files"}
      </button>
      {error && <p role="alert" className="ids-bundle-error">{error}</p>}
      {result && (
        <div className="ids-bundle-result" aria-live="polite">
          <div className="ids-bundle-metrics">
            <div><span>Rule files reviewed</span><strong>{result.summary.rule_files_uploaded}</strong></div>
            <div><span>Enabled rules visible</span><strong>{result.summary.enabled_rules_visible}</strong></div>
            <div><span>Findings</span><strong>{result.summary.total_findings}</strong></div>
            <div><span>Security score</span><strong>Not assigned</strong></div>
          </div>
          <p className="ids-bundle-note">Referenced entries: {result.coverage.referenced_files.entries_visible}; filename-only candidates: {result.coverage.referenced_files.filename_candidate_matches}; not uploaded: {result.coverage.referenced_files.not_uploaded}.</p>
          <p className="ids-bundle-note">{result.notice}</p>
          {result.findings.length === 0 ? <p>No issues detected by the supported rule-text checks.</p> : (
            <div className="ids-bundle-findings">
              {result.findings.map((finding, index) => (
                <article key={`${finding.code}-${index}`} className="ids-bundle-finding">
                  <div className="ids-bundle-finding-top"><strong>{finding.title}</strong><span>{finding.severity}</span></div>
                  <p>{finding.description}</p>
                  <p><strong>Source:</strong> {finding.evidence.filename}{finding.evidence.line_number ? `, line ${finding.evidence.line_number}` : ""}</p>
                  <p><strong>Recommendation:</strong> {finding.recommendation}</p>
                </article>
              ))}
            </div>
          )}
          {result.warnings.map((warning, index) => <p key={index} className="ids-bundle-note">{warning}</p>)}
        </div>
      )}
    </section>
  );
}
