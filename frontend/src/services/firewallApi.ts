
/**
 * API-004: Firewall Analyzer API Client
 *
 * Connects the React frontend to the FastAPI backend.
 *
 * Endpoint:
 * POST /api/v1/analyze
 *
 * Features:
 * - Upload Cisco ASA configuration files
 * - Receive security analysis reports
 * - Receive parsed firewall configuration data
 * - Handle network and API errors
 * - Reuse existing dashboard report types
 */

import type {
  Finding as ReportFinding,
  FirewallReport,
} from "../types/report";

/* ============================================================
   EXISTING DASHBOARD TYPE COMPATIBILITY
   ============================================================ */

export type Finding = ReportFinding;

export type ReportSummary = FirewallReport["summary"];

/* ============================================================
   FIREWALL CONFIGURATION TYPES
   ============================================================ */

export interface FirewallRule {
  id: number;
  line_number: number;
  name: string | null;
  action: string;
  protocol: string;
  source: string[];
  destination: string[];
  source_ports: number[];
  destination_ports: number[];
  source_services: string[];
  destination_services: string[];
  source_interface: string | null;
  destination_interface: string | null;
  logging: boolean;
  disabled: boolean;
  description: string | null;
  raw_config: string;
}

export interface NATRule {
  id: number;
  source: string;
  translated_source: string;
  destination: string;
  translated_destination: string;
  protocol: string;
  source_port: number | null;
  destination_port: number | null;
  line_number: number | null;
  raw_config: string;
}

export interface FirewallRoute {
  destination: string;
  next_hop: string;
  interface: string;
  metric: number | null;
  line_number: number | null;
  raw_config: string;
}

export interface FirewallInterface {
  name: string;
  security_zone: string;
  ip_address: string;
  description: string;
  enabled: boolean;
}

/**
 * Network and service objects can contain additional
 * parser-specific fields.
 */
export interface ConfigurationObject {
  name: string;
  [key: string]: unknown;
}

export interface FirewallConfiguration {
  interfaces: FirewallInterface[];
  network_objects: ConfigurationObject[];
  service_objects: ConfigurationObject[];
  rules: FirewallRule[];
  nat_rules: NATRule[];
  routes: FirewallRoute[];
}

/* ============================================================
   API ANALYSIS RESPONSE
   ============================================================ */

/**
 * The existing FirewallReport type requires source metadata.
 *
 * The FastAPI endpoint currently returns the analysis report
 * without a source field, so source is optional here.
 *
 * All other report fields reuse the existing dashboard types.
 */
export interface AnalysisResponse
  extends Omit<FirewallReport, "source"> {
  configuration: FirewallConfiguration;
  source?: FirewallReport["source"];
}

/* ============================================================
   API CONFIGURATION
   ============================================================ */

const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ??
  "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const ANALYZE_ENDPOINT = `${API_BASE_URL}/api/v1/analyze`;

const MAX_FILE_SIZE = 2 * 1024 * 1024;

const ALLOWED_EXTENSIONS = [".conf", ".cfg", ".txt"];

/* ============================================================
   FILE VALIDATION
   ============================================================ */

function validateFirewallFile(file: File): void {
  if (!file) {
    throw new Error(
      "Please select a firewall configuration file."
    );
  }

  if (file.size === 0) {
    throw new Error(
      "The selected configuration file is empty."
    );
  }

  if (file.size > MAX_FILE_SIZE) {
    throw new Error(
      "Configuration file must not exceed 2 MiB."
    );
  }

  const filename = file.name.toLowerCase();

  const validExtension = ALLOWED_EXTENSIONS.some(
    (extension) => filename.endsWith(extension)
  );

  if (!validExtension) {
    throw new Error(
      "Unsupported file format. Use .conf, .cfg, or .txt."
    );
  }
}

/* ============================================================
   API ERROR HANDLING
   ============================================================ */

function getApiErrorMessage(
  data: unknown,
  status: number
): string {
  if (
    data !== null &&
    typeof data === "object" &&
    "detail" in data
  ) {
    const detail = data.detail;

    if (typeof detail === "string") {
      return detail;
    }

    if (Array.isArray(detail)) {
      const messages = detail
        .map((item: unknown) => {
          if (
            item !== null &&
            typeof item === "object" &&
            "msg" in item &&
            typeof item.msg === "string"
          ) {
            return item.msg;
          }

          return null;
        })
        .filter((message): message is string =>
          message !== null
        );

      if (messages.length > 0) {
        return messages.join("; ");
      }
    }
  }

  return `Firewall analysis failed (HTTP ${status}).`;
}

/* ============================================================
   RESPONSE VALIDATION
   ============================================================ */

/**
 * Performs basic structural validation before returning
 * the API response to React.
 *
 * This is not a complete schema validator. It verifies the
 * fields required by the dashboard.
 */
function isAnalysisResponse(
  data: unknown
): data is AnalysisResponse {
  if (
    data === null ||
    typeof data !== "object"
  ) {
    return false;
  }

  if (
    !("vendor" in data) ||
    typeof data.vendor !== "string" ||
    !("hostname" in data) ||
    typeof data.hostname !== "string"
  ) {
    return false;
  }

  if (
    !("summary" in data) ||
    data.summary === null ||
    typeof data.summary !== "object"
  ) {
    return false;
  }

  const summary = data.summary;

  if (
    !("security_score" in summary) ||
    typeof summary.security_score !== "number" ||
    !("risk_level" in summary) ||
    typeof summary.risk_level !== "string" ||
    !("total_findings" in summary) ||
    typeof summary.total_findings !== "number"
  ) {
    return false;
  }

  if (
    !("findings" in data) ||
    !Array.isArray(data.findings) ||
    !("warnings" in data) ||
    !Array.isArray(data.warnings)
  ) {
    return false;
  }

  if (
    !("configuration" in data) ||
    data.configuration === null ||
    typeof data.configuration !== "object"
  ) {
    return false;
  }

  const configuration = data.configuration;

  const requiredCollections = [
    "interfaces",
    "network_objects",
    "service_objects",
    "rules",
    "nat_rules",
    "routes",
  ];

  return requiredCollections.every(
    (key) =>
      key in configuration &&
      Array.isArray(
        configuration[
          key as keyof typeof configuration
        ]
      )
  );
}

/* ============================================================
   ANALYZE FIREWALL
   ============================================================ */

/**
 * Uploads a Cisco ASA configuration to FastAPI.
 *
 * @param file - Configuration file selected by the user.
 * @returns Parsed configuration and security analysis.
 */
export async function analyzeFirewall(
  file: File
): Promise<AnalysisResponse> {
  validateFirewallFile(file);

  const formData = new FormData();

  formData.append("file", file);

  let response: Response;

  try {
    response = await fetch(ANALYZE_ENDPOINT, {
      method: "POST",
      body: formData,
    });
  } catch {
    throw new Error(
      "Cannot connect to the firewall analyzer API. " +
      "Make sure FastAPI is running at " +
      API_BASE_URL
    );
  }

  let data: unknown;

  try {
    data = await response.json();
  } catch {
    throw new Error(
      "The firewall analyzer returned an invalid JSON response."
    );
  }

  if (!response.ok) {
    throw new Error(
      getApiErrorMessage(data, response.status)
    );
  }

  if (!isAnalysisResponse(data)) {
    throw new Error(
      "Unexpected API response structure. " +
      "Verify that the backend includes API-003 " +
      "configuration serialization."
    );
  }

  return data;
}
