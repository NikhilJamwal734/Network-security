import React from "react";
import { createRoot } from "react-dom/client";
import Logs from "./pages/Logs";
import "./index.css";

function JsonLogsPage() {
  return (
    <main style={{ maxWidth: 1400, margin: "0 auto", padding: "18px 20px" }}>
      <nav aria-label="Return to analyzer" style={{ marginBottom: 16 }}>
        <a href="/" style={{ color: "#93c5fd", fontSize: 13, textDecoration: "none" }}>
          ← Back to Firewall Analyzer
        </a>
      </nav>
      <Logs />
    </main>
  );
}

const target = document.getElementById("root");
if (!target) throw new Error("Log viewer root element is missing");
createRoot(target).render(
  <React.StrictMode>
    <JsonLogsPage />
  </React.StrictMode>
);
