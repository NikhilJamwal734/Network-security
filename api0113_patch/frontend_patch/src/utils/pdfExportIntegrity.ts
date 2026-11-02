/** Basic generated-PDF verification before a browser download is initiated.
 * This is not equivalent to parsing every PDF page or checking visual fidelity.
 */
export interface PdfExportInspection {
  ok: boolean;
  pageCount: number;
  byteLength: number;
  problems: string[];
}

export function inspectPdfExport(bytes: Uint8Array, pageCount: number): PdfExportInspection {
  const problems: string[] = [];
  if (bytes.byteLength < 256 || bytes.byteLength > 100 * 1024 * 1024) {
    problems.push("PDF file is unusually small or exceeds the 100 MB export limit");
  }
  const marker = [37, 80, 68, 70, 45]; // %PDF-
  if (bytes.length < marker.length || marker.some((x, i) => bytes[i] !== x)) {
    problems.push("PDF header is missing");
  }
  if (!Number.isInteger(pageCount) || pageCount < 1 || pageCount > 2000) {
    problems.push("PDF page count is invalid or exceeds the supported limit");
  }
  // jsPDF places %%EOF at the end; allow trailing CR/LF and whitespace.
  const end = bytes.subarray(Math.max(0, bytes.length - 1024));
  const eof = [37, 37, 69, 79, 70];
  let found = false;
  for (let i = 0; i <= end.length - eof.length; i += 1) {
    if (eof.every((x, j) => end[i + j] === x)) {
      found = true;
      for (let j = i + eof.length; j < end.length; j += 1) {
        if (![9, 10, 12, 13, 32].includes(end[j])) { found = false; break; }
      }
      if (found) break;
    }
  }
  if (!found) problems.push("PDF end-of-file marker is missing or invalid");
  return { ok: problems.length === 0, pageCount, byteLength: bytes.length, problems };
}

export function downloadVerifiedPdf(data: ArrayBuffer, filename: string): void {
  const blob = new Blob([data], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  try { anchor.click(); }
  finally {
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
  }
}
