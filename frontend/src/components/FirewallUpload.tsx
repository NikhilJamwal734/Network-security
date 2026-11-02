import { useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { useAnalysis } from "../context/AnalysisContext";
import "./FirewallUpload.css";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".conf", ".cfg", ".txt"];

function FolderIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
      <path d="M12 11v6m-3-3h6" />
    </svg>
  );
}

function AnalyzeIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function FirewallUpload() {
  const { analyze, analysis, loading, filename } = useAnalysis();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0] ?? null;
    setLocalError(null);
    setSelectedFile(null);

    if (!file) return;

    if (!ALLOWED_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext))) {
      setLocalError("Select a .conf, .cfg, or .txt configuration file.");
      event.target.value = "";
      return;
    }
    if (file.size === 0) {
      setLocalError("The selected configuration file is empty.");
      event.target.value = "";
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setLocalError("The selected file exceeds the 2 MiB upload limit.");
      event.target.value = "";
      return;
    }

    setSelectedFile(file);
  }

  async function handleAnalyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedFile || loading) return;
    setLocalError(null);

    try {
      await analyze(selectedFile);
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : "Unable to analyze the selected file.");
    }
  }

  const displayFilename = selectedFile?.name ?? (analysis && filename ? filename : "No file selected");

  return (
    <form className="fa-upload" onSubmit={handleAnalyze}>
      <div className="fa-upload-heading">
        <div>
          <h2>Analyze a firewall configuration</h2>
          <p>Select a Cisco ASA configuration file to run security checks.</p>
        </div>
        <span className="fa-upload-format">CONF · CFG · TXT</span>
      </div>

      <input
        ref={fileInputRef}
        className="fa-upload-native-input"
        type="file"
        accept=".conf,.cfg,.txt,text/plain"
        aria-label="Select firewall configuration file"
        onChange={handleFileChange}
        disabled={loading}
      />

      <div className="fa-upload-controls">
        <div className="fa-upload-file-group">
          <button
            type="button"
            className="fa-upload-select"
            onClick={() => fileInputRef.current?.click()}
            disabled={loading}
          >
            <FolderIcon />
            <span>Choose File</span>
          </button>
          <span className="fa-upload-filename" title={displayFilename} aria-live="polite">
            {displayFilename}
          </span>
        </div>

        <button
          type="submit"
          className="fa-upload-analyze"
          disabled={loading || !selectedFile}
        >
          {loading ? (
            <span className="fa-upload-spinner" aria-hidden="true" />
          ) : (
            <AnalyzeIcon />
          )}
          <span>{loading ? "Analyzing..." : "Analyze Configuration"}</span>
        </button>
      </div>

      <div className="fa-upload-help">
        Maximum file size: 2 MiB. Uploaded configuration is analyzed as data, never executed.
      </div>
      {localError && <p className="fa-upload-error" role="alert">{localError}</p>}
    </form>
  );
}

export default FirewallUpload;
