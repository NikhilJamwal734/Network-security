
import { useAnalysis } from "../context/AnalysisContext";

import "./AnalysisFeedback.css";

function AnalysisFeedback() {
  const { loading, error } = useAnalysis();

  if (loading) {
    return (
      <div
        className="fa-analysis-feedback fa-analysis-loading"
        role="status"
        aria-live="polite"
      >
        <span
          className="fa-loading-spinner"
          aria-hidden="true"
        />

        <div className="fa-feedback-content">
          <strong>Analyzing firewall configuration</strong>

          <p>
            Parsing Cisco ASA configuration and checking
            firewall security rules...
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div
        className="fa-analysis-feedback fa-analysis-error"
        role="alert"
      >
        <span
          className="fa-feedback-icon"
          aria-hidden="true"
        >
          !
        </span>

        <div className="fa-feedback-content">
          <strong>Analysis could not be completed</strong>

          <p>{error}</p>
        </div>
      </div>
    );
  }

  return null;
}

export default AnalysisFeedback;
