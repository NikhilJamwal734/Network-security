/** Read the existing universal analyzer's *structured* parsed inventory.
 * Normalized report remains unchanged. Uploads are processed only as untrusted data.
 */
export interface PlatformDetails {
  platform_id: string;
  configuration: Record<string, unknown>;
  warnings: string[];
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const apiBase = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

export async function getPlatformDetails(
  file: File,
  platformId: string,
  signal?: AbortSignal,
): Promise<PlatformDetails> {
  const form = new FormData();
  form.append("file", file, file.name);
  const query = new URLSearchParams({ platform: platformId });
  const response = await fetch(`${apiBase}/api/v1/analyze/universal?${query}`, {
    method: "POST", body: form, signal,
  });
  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(`Configuration inventory request failed (HTTP ${response.status}).`);
  }
  if (!record(data) || !record(data.platform_detection) ||
      data.platform_detection.platform_id !== platformId || !record(data.configuration)) {
    throw new Error("The universal API did not return matching structured configuration details.");
  }
  return {
    platform_id: platformId,
    configuration: data.configuration,
    warnings: Array.isArray(data.warnings) ? data.warnings.filter((x): x is string => typeof x === "string") : [],
  };
}
