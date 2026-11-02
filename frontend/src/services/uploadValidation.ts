
/**
 * API-008.1
 * Client-side firewall configuration upload validation.
 *
 * These checks improve usability. The FastAPI backend
 * must remain responsible for enforcing upload security.
 */

export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;

export const ALLOWED_EXTENSIONS = [
  ".conf",
  ".cfg",
  ".txt",
] as const;

export async function validateFirewallFile(
  file: File
): Promise<void> {
  if (!file) {
    throw new Error(
      "Please select a firewall configuration file."
    );
  }

  const filename = file.name.trim();

  if (!filename) {
    throw new Error(
      "The selected file must have a filename."
    );
  }

  const hasValidExtension =
    ALLOWED_EXTENSIONS.some((extension) =>
      filename.toLowerCase().endsWith(extension)
    );

  if (!hasValidExtension) {
    throw new Error(
      "Unsupported file type. Select a .conf, .cfg, or .txt file."
    );
  }

  if (file.size === 0) {
    throw new Error(
      "The selected configuration file is empty."
    );
  }

  if (file.size > MAX_UPLOAD_BYTES) {
    throw new Error(
      "The configuration file is too large. Maximum size: 2 MiB."
    );
  }

  let bytes: ArrayBuffer;

  try {
    bytes = await file.arrayBuffer();
  } catch {
    throw new Error(
      "Unable to read the selected file. Try selecting it again."
    );
  }

  let text: string;

  try {
    const decoder = new TextDecoder("utf-8", {
      fatal: true,
    });

    text = decoder.decode(bytes);
  } catch {
    throw new Error(
      "Invalid file encoding. Configuration files must use UTF-8."
    );
  }

  if (text.trim().length === 0) {
    throw new Error(
      "The configuration file contains only whitespace."
    );
  }

  // Reject binary files masquerading as text configurations.
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(text)) {
    throw new Error(
      "The selected file contains binary or unsupported control characters."
    );
  }
}
