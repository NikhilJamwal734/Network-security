import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import {
  analyzeNormalized,
  filenameExtension,
  getSupportedPlatforms,
  MAX_CONFIG_BYTES,
  SUPPORTED_FILE_EXTENSIONS,
  type NormalizedReport,
  type Severity,
  type SupportedPlatform,
} from "../api/universal";
import { F5_PLATFORM_ID, withF5Platform, analyzeF5Phase1 } from "../api/f5Phase1";
import { useAnalysis } from "../context/AnalysisContext";
import CiscoASAOverview from "./CiscoASAOverview";
import "./UniversalAnalysis.css";
import "./UnifiedDashboardExtras.css";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];
const TITLE = "Security Dashboard";

/** A single upload and report flow for Cisco ASA, FortiOS, Snort, and Suricata. */
interface UnifiedDashboardProps {
  report: NormalizedReport | null;
  onReportChange: (report: NormalizedReport | null) => void;
  legacyASAReady: boolean;
  onLegacyASAReadyChange: (ready: boolean) => void;
}


function niceLabel(text: string): string {
  return text.replace(/_/g, " ").replace(/\b\w/g, (s) => s.toUpperCase());
}

function safeExportName(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 90) || "configuration";
}

function exportReport(report: NormalizedReport, name: string) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${safeExportName(name)}.normalized.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function UniversalAnalysis({
  report, onReportChange, legacyASAReady, onLegacyASAReadyChange,
}: UnifiedDashboardProps) {
  // Existing ASA detail pages and JSON/PDF exporters still rely on AnalysisContext.
  // The normalized API does not include legacy ASA rule/NAT/object inventories.
  const {
    analyze: analyzeLegacyASA,
    analysis: legacyReport,
    filename: legacyFilename,
    loading: legacyLoading,
    error: legacyError,
  } = useAnalysis();
  const [pendingASA, setPendingASA] = useState<{
    filename: string;
    previousAnalysis: typeof legacyReport;
  } | null>(null);
  const [asaSyncError, setAsaSyncError] = useState<string | null>(null);

  const [platforms, setPlatforms] = useState<SupportedPlatform[]>([]);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [loadingCatalog, setLoadingCatalog] = useState(true);
  const [choice, setChoice] = useState("auto");
  const [file, setFile] = useState<File | null>(null);
  const [analyzedFile, setAnalyzedFile] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const inFlight = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    getSupportedPlatforms(controller.signal)
      .then((list) => { if (!controller.signal.aborted) setPlatforms(withF5Platform(list)); })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setCatalogError(reason instanceof Error ? reason.message : "Unable to load supported platforms.");
        }
      })
      .finally(() => { if (!controller.signal.aborted) setLoadingCatalog(false); });
    return () => controller.abort();
  }, []);

  useEffect(() => () => inFlight.current?.abort(), []);

  // Mark the legacy ASA detail views ready only after AnalysisContext has
  // received a NEW response for the same uploaded filename. This prevents
  // old ASA findings/exports from appearing for a later upload.
  useEffect(() => {
    if (!pendingASA) return;
    if (legacyError && !legacyLoading) {
      setAsaSyncError(legacyError);
      setPendingASA(null);
      onLegacyASAReadyChange(false);
      return;
    }
    if (!legacyLoading && legacyReport &&
        legacyReport !== pendingASA.previousAnalysis &&
        legacyFilename === pendingASA.filename) {
      onLegacyASAReadyChange(true);
      setPendingASA(null);
      setAsaSyncError(null);
    }
  }, [pendingASA, legacyReport, legacyFilename, legacyLoading, legacyError, onLegacyASAReadyChange]);


  function cancelCurrent() {
    inFlight.current?.abort();
    inFlight.current = null;
    setBusy(false);
  }

  function selectFile(event: ChangeEvent<HTMLInputElement>) {
    cancelCurrent();
    setError(null);
    onReportChange(null);
    onLegacyASAReadyChange(false);
    setPendingASA(null);
    setAsaSyncError(null);
    setSeverityFilter("all");
    setFile(event.target.files?.[0] ?? null);
  }

  function setPlatformChoice(platformId: string) {
    cancelCurrent();
    setChoice(platformId);
    onReportChange(null);
    onLegacyASAReadyChange(false);
    setPendingASA(null);
    setAsaSyncError(null);
    setError(null);
    setSeverityFilter("all");
  }

  const extension = file ? filenameExtension(file.name) : "";
  const platform = platforms.find((p) => p.platform_id === choice);
  const validExtension = SUPPORTED_FILE_EXTENSIONS.some((e) => e === extension);
  const fitsSelectedPlatform = choice === "auto" || !!platform?.extensions.includes(extension);
  const needsRuleChoice = choice === "auto" && extension === ".rules";
  const badSize = !!file && (file.size === 0 || file.size > MAX_CONFIG_BYTES);
  const canSubmit = !!file && !busy && !loadingCatalog && !catalogError && validExtension &&
    fitsSelectedPlatform && !needsRuleChoice && !badSize;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit || !file) return;
    cancelCurrent();
    const controller = new AbortController();
    inFlight.current = controller;
    setBusy(true);
    setError(null);
    onReportChange(null);
    onLegacyASAReadyChange(false);
    setPendingASA(null);
    setAsaSyncError(null);
    try {
      const next = choice === F5_PLATFORM_ID
        ? await analyzeF5Phase1(file, controller.signal)
        : await analyzeNormalized(file, choice === "auto" ? null : choice, controller.signal);
      if (inFlight.current !== controller || controller.signal.aborted) return;
      onReportChange(next);
      setAnalyzedFile(file.name);

      // Only Cisco ASA needs the legacy report as well: existing firewall rule,
      // object, NAT, route and PDF pages consume its richer data structure.
      // One user upload action; two distinct backend representations for ASA.
      if (next.platform.platform_id === "cisco_asa") {
        setPendingASA({ filename: file.name, previousAnalysis: legacyReport });
        try {
          await analyzeLegacyASA(file);
        } catch (reason) {
          if (inFlight.current === controller && !controller.signal.aborted) {
            setAsaSyncError(reason instanceof Error ? reason.message : "ASA details unavailable.");
            setPendingASA(null);
          }
        }
      }
    } catch (reason) {
      if (inFlight.current === controller && !controller.signal.aborted) {
        setError(reason instanceof Error ? reason.message : "Unable to analyze the configuration.");
      }
    } finally {
      if (inFlight.current === controller) {
        inFlight.current = null;
        setBusy(false);
      }
    }
  }

  const visibleFindings = report?.findings.filter((finding) =>
    severityFilter === "all" || finding.severity === severityFilter
  ) ?? [];

  return (
    <div className="ua-page">
      <header className="ua-heading">
        <div>
          <p className="ua-eyebrow">SECURITY ANALYSIS / DASHBOARD</p>
          <h1>{TITLE}</h1>
          <p>One upload for Cisco ASA, FortiOS, Snort, and Suricata. Explore normalized security findings and available device details.</p>
        </div>
        <span className="ua-pill">Static analysis only</span>
      </header>

      <section className="ua-panel" aria-labelledby="ua-upload-heading">
        <div className="ua-section-heading">
          <div>
            <h2 id="ua-upload-heading">Upload a configuration</h2>
            <p>Select a registered platform, or use automatic detection for identifiable configurations.</p>
          </div>
        </div>
        <form className="ua-upload-form" onSubmit={submit}>
          <div className="ua-upload-fields">
            <label className="ua-field">
              <span>Platform</span>
              <select
                value={choice}
                onChange={(event: ChangeEvent<HTMLSelectElement>) => setPlatformChoice(event.target.value)}
                disabled={loadingCatalog || busy || !!catalogError}
                aria-label="Select security platform"
              >
                <option value="auto">Automatic detection</option>
                {platforms.map((p) => (
                  <option key={p.platform_id} value={p.platform_id}>
                    {p.display_name} ({p.family.toUpperCase()})
                  </option>
                ))}
              </select>
            </label>
            <label className="ua-field">
              <span>Configuration file</span>
              <input
                type="file"
                accept={SUPPORTED_FILE_EXTENSIONS.join(",")}
                onChange={selectFile}
                disabled={busy}
                aria-label="Choose configuration file"
              />
            </label>
          </div>
          <p className="ua-hint">
            Formats: .conf, .cfg, .txt, .rules, .yaml, .yml · Up to 2 MiB.
            Standalone .rules files need explicit Snort or Suricata selection.
          </p>
          {loadingCatalog && <p role="status" className="ua-hint">Loading supported platforms…</p>}
          {catalogError && <p role="alert" className="ua-alert ua-alert-error">Platform discovery failed: {catalogError}. Check the backend at http://127.0.0.1:8000.</p>}
          {file && !validExtension && <p role="alert" className="ua-alert ua-alert-error">Unsupported file extension.</p>}
          {badSize && <p role="alert" className="ua-alert ua-alert-error">Choose a nonempty configuration no larger than 2 MiB.</p>}
          {file && validExtension && !fitsSelectedPlatform && (
            <p role="alert" className="ua-alert ua-alert-error">The selected platform does not support {extension} files.</p>
          )}
          {needsRuleChoice && (
            <p role="alert" className="ua-alert ua-alert-info">Snort and Suricata share rule syntax. Select one explicitly before analyzing a .rules file.</p>
          )}
          <div className="ua-actions">
            <button type="submit" className="ua-primary" disabled={!canSubmit}>
              {busy ? "Analyzing configuration…" : "Analyze configuration"}
            </button>
            {busy && <button type="button" className="ua-secondary" onClick={cancelCurrent}>Cancel</button>}
          </div>
        </form>
        {error && <p className="ua-alert ua-alert-error" role="alert">{error}</p>}
      </section>

      {!report && !busy && !error && (
        <div className="ua-empty">
          <h2>No analysis yet</h2>
          <p>Select a file and a platform to begin. Cisco ASA detail pages become available after a successful ASA analysis.</p>
        </div>
      )}
      {busy && <p className="ua-panel ua-loading" role="status" aria-live="polite">Analyzing uploaded configuration text…</p>}

      {report && (
        <div className="ua-results" aria-live="polite">
          <section className="ua-panel">
            <div className="ua-section-heading ua-space-between">
              <div>
                <p className="ua-eyebrow">NORMALIZED REPORT · SCHEMA {report.schema_version}</p>
                <h2>{report.platform.display_name}</h2>
                <p>{report.platform.family.toUpperCase()} · {report.platform.detection_method ?? "Unknown"} selection
                  {report.platform.hostname ? ` · ${report.platform.hostname}` : ""}</p>
              </div>
              <button className="ua-secondary" type="button" onClick={() => exportReport(report, analyzedFile)}>
                Export normalized JSON
              </button>
            </div>
            <div className="ua-metrics">
              <div className="ua-metric"><span>Total findings</span><strong>{report.summary.total_findings}</strong></div>
              <div className="ua-metric"><span>Security score</span><strong>{report.summary.security_score === null ? "Not scored" : `${report.summary.security_score}/100`}</strong></div>
              <div className="ua-metric"><span>Risk level</span><strong>{report.summary.risk_level ?? "Not assigned"}</strong></div>
              <div className="ua-metric"><span>Assessment</span><strong>Static config</strong></div>
            </div>
            <p className="ua-hint">Scores are platform-specific and must not be compared across vendors. “Not scored” is not a zero score.</p>
          </section>

          <section className="ua-panel">
            <h2>Severity distribution</h2>
            <div className="ua-severities" aria-label="Finding counts by severity">
              {SEVERITIES.map((s) => (
                <div className={`ua-severity ua-${s}`} key={s}>
                  <span>{niceLabel(s)}</span>
                  <strong>{report.summary.severity_counts[s]}</strong>
                </div>
              ))}
            </div>
          </section>

          {report.platform.platform_id === "cisco_asa" && (
            <section className="ua-panel ua-asa-panel" aria-label="Cisco ASA configuration details">
              {legacyASAReady ? (
                <CiscoASAOverview />
              ) : (
                <div>
                  <h2>Cisco ASA configuration details</h2>
                  <p className="ua-hint">
                    {asaSyncError || (legacyError && !legacyLoading)
                      ? "The normalized security report is available, but the legacy Cisco ASA detail report could not be loaded."
                      : "Preparing firewall rules, network objects, services, NAT and route details…"}
                  </p>
                  {(asaSyncError || (legacyError && !legacyLoading)) &&
                    <p role="alert" className="ua-alert ua-alert-error">{asaSyncError || legacyError}</p>}
                </div>
              )}
            </section>
          )}

          <section className="ua-panel">
            <div className="ua-section-heading ua-space-between">
              <div>
                <h2>Security findings</h2>
                <p>Checks are limited to the parser and rules implemented for this platform.</p>
              </div>
              <label className="ua-filter">
                <span>Severity</span>
                <select value={severityFilter} onChange={(e: ChangeEvent<HTMLSelectElement>) => setSeverityFilter(e.target.value as Severity | "all")}>
                  <option value="all">All findings</option>
                  {SEVERITIES.map((s) => <option key={s} value={s}>{niceLabel(s)}</option>)}
                </select>
              </label>
            </div>
            <p className="ua-hint">Showing {visibleFindings.length} of {report.summary.total_findings} findings.</p>
            {visibleFindings.length === 0 && <p className="ua-empty-small">No findings match this filter.</p>}
            <div className="ua-findings">
              {visibleFindings.map((finding) => (
                <article className="ua-finding" key={finding.finding_id}>
                  <div className="ua-finding-top">
                    <span className={`ua-tag ua-${finding.severity}`}>{niceLabel(finding.severity)}</span>
                    <span className="ua-code">{finding.code}</span>
                  </div>
                  <h3>{finding.title}</h3>
                  <p>{finding.description}</p>
                  {finding.recommendation && <p><strong>Recommendation:</strong> {finding.recommendation}</p>}
                  <p className="ua-evidence">
                    {finding.evidence.line_number !== null && `Line ${finding.evidence.line_number} · `}
                    {finding.evidence.rule_id !== null && `Rule ${finding.evidence.rule_id} · `}
                    ID: {finding.finding_id}
                  </p>
                </article>
              ))}
            </div>
          </section>

          <section className="ua-panel">
            <h2>Analysis coverage</h2>
            <p className="ua-hint">“Assessed” means the implemented checks ran; it does not mean full feature coverage.</p>
            <div className="ua-coverage">
              {report.coverage.domains.map((domain) => (
                <div className="ua-coverage-row" key={domain.domain}>
                  <span>{niceLabel(domain.domain)}</span>
                  <span className={domain.status === "assessed" ? "ua-status-assessed" : "ua-status-unassessed"}>
                    {domain.status === "assessed" ? "Assessed" : "Not assessed"}
                  </span>
                </div>
              ))}
            </div>
            {report.coverage.limitations.length > 0 && (
              <div className="ua-limits">
                <h3>Limitations</h3>
                <ul>{report.coverage.limitations.map((item, i) => <li key={`${i}-${item}`}>{item}</li>)}</ul>
              </div>
            )}
          </section>
          {report.warnings.length > 0 && (
            <section className="ua-panel" aria-labelledby="ua-warnings">
              <h2 id="ua-warnings">Parser warnings</h2>
              <ul>{report.warnings.map((warning, i) => <li key={`${i}-${warning}`}>{warning}</li>)}</ul>
            </section>
          )}
        </div>
      )}
    </div>
  );
}

export default UniversalAnalysis;
