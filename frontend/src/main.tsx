import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App";
import { AnalysisProvider } from "./context/AnalysisContext";

import "./index.css";

ReactDOM.createRoot(
  document.getElementById("root")!,
).render(
  <React.StrictMode>
    <AnalysisProvider>
      <App />
    </AnalysisProvider>
  </React.StrictMode>,
);