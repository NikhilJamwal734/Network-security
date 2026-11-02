// /**
//  * Loads the firewall analyzer report.
//  *
//  * This module is intentionally framework-agnostic: it has no
//  * dependency on React (no hooks, no JSX) so it can be unit tested and
//  * reused from any component, store, or script.
//  */

// import type { FirewallReport } from "../types/report";

// /** Default location the backend writes reports/firewall_report.json to when served statically. */
// export const DEFAULT_REPORT_URL = "/reports/firewall_report.json";

// /** Thrown when a report fails to load or does not look like a valid FirewallReport. */
// export class ReportLoadError extends Error {
//   readonly cause?: unknown;

//   constructor(message: string, cause?: unknown) {
//     super(message);
//     this.name = "ReportLoadError";
//     this.cause = cause;
//   }
// }

// /**
//  * Narrow, defensive runtime check that `value` has the shape of a
//  * `FirewallReport`. This does not replace a schema validation library —
//  * it only guards against obviously malformed data (e.g. an HTML error
//  * page fetched instead of JSON, or a differently-shaped report).
//  */
// function isFirewallReport(value: unknown): value is FirewallReport {
//   if (typeof value !== "object" || value === null) {
//     return false;
//   }

//   const report = value as Record<string, unknown>;

//   if (
//     typeof report.vendor !== "string" ||
//     typeof report.hostname !== "string" ||
//     !Array.isArray(report.findings) ||
//     !Array.isArray(report.warnings) ||
//     typeof report.summary !== "object" ||
//     report.summary === null
//   ) {
//     return false;
//   }

//   const summary = report.summary as Record<string, unknown>;

//   return (
//     typeof summary.total_rules === "number" &&
//     typeof summary.security_score === "number" &&
//     typeof summary.risk_level === "string"
//   );
// }

// /**
//  * Fetch and parse the firewall report from `url` (a static JSON file
//  * or an API endpoint that returns the same shape).
//  *
//  * @param url Location of the report JSON. Defaults to {@link DEFAULT_REPORT_URL}.
//  * @throws {ReportLoadError} if the request fails, the response is not
//  *   valid JSON, or the parsed JSON doesn't look like a `FirewallReport`.
//  */
// export async function loadReport(
//   url: string = DEFAULT_REPORT_URL,
// ): Promise<FirewallReport> {
//   let response: Response;

//   try {
//     response = await fetch(url);
//   } catch (error) {
//     throw new ReportLoadError(`Failed to fetch report from "${url}".`, error);
//   }

//   if (!response.ok) {
//     throw new ReportLoadError(
//       `Failed to fetch report from "${url}": ${response.status} ${response.statusText}.`,
//     );
//   }

//   let data: unknown;

//   try {
//     data = await response.json();
//   } catch (error) {
//     throw new ReportLoadError(
//       `Report at "${url}" did not contain valid JSON.`,
//       error,
//     );
//   }

//   if (!isFirewallReport(data)) {
//     throw new ReportLoadError(
//       `Report at "${url}" does not match the expected FirewallReport shape.`,
//     );
//   }

//   return data;
// }

// /**
//  * Parse a `FirewallReport` from a raw JSON string (e.g. read from a
//  * local file input or a test fixture), without performing a network
//  * request.
//  *
//  * @throws {ReportLoadError} if the text isn't valid JSON or doesn't
//  *   look like a `FirewallReport`.
//  */
// export function parseReport(jsonText: string): FirewallReport {
//   let data: unknown;

//   try {
//     data = JSON.parse(jsonText);
//   } catch (error) {
//     throw new ReportLoadError("Report text is not valid JSON.", error);
//   }

//   if (!isFirewallReport(data)) {
//     throw new ReportLoadError(
//       "Parsed report does not match the expected FirewallReport shape.",
//     );
//   }

//   return data;
// }


import type { FirewallReport } from "../types/report";

const REPORT_URL = "/reports/firewall_report.json";

export async function loadFirewallReport(
  signal?: AbortSignal
): Promise<FirewallReport> {
  const response = await fetch(REPORT_URL, {
    method: "GET",
    cache: "no-store",
    signal,
  });

  if (!response.ok) {
    throw new Error(
      `Failed to load firewall_report.json (${response.status})`
    );
  }

  const report = (await response.json()) as FirewallReport;

  return report;
}