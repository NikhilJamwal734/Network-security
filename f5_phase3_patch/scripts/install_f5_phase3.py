"""F5 Phase 3: add optional operator-evidence JSON upload to existing React F5 flow.

Fail closed on changed anchors, non-UTF8, symlinks, or backup conflicts.
No changes to Python analyzer or other vendors. This installer never handles secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ADAPTER = 'frontend/src/api/f5Phase1.ts'
PAGE = 'frontend/src/pages/UniversalAnalysis.tsx'
API = 'app/f5_phase1_addon/api.py'
PHASE2 = 'app/f5_phase2_addon/review.py'
MANIFEST = '.f5_phase3_manifest.json'
BACKUP_DIR = '.f5_phase3_backups'
FILES = (ADAPTER, PAGE)

ADAPTER_HELPER = '''/** Optional F5 Phase 2 operator assertions. This is metadata, not a UCS archive.
 * Checks are for user feedback only. The FastAPI backend validates again.
 */
const F5_EVIDENCE_MAX_BYTES = 16_384;
const F5_UPDATE_STATUSES = ["current", "unknown", "failed", "disabled", "manual", "scheduled", "outdated"];

function isF5Record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCalendarDate(value: string): boolean {
  if (!/^\\d{4}-\\d{2}-\\d{2}$/.test(value)) return false;
  const date = new Date(value + "T00:00:00Z");
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

async function readF5OperatorEvidence(file: File, signal?: AbortSignal): Promise<string> {
  if (!/\\.json$/i.test(file.name) || file.size === 0 || file.size > F5_EVIDENCE_MAX_BYTES) {
    throw new Error("F5 evidence must be a nonempty .json file of at most 16 KiB.");
  }
  const raw = (await file.text()).replace(/^\\uFEFF/, "");
  if (signal?.aborted) throw new Error("F5 evidence read cancelled.");
  let value: unknown;
  try { value = JSON.parse(raw); }
  catch { throw new Error("F5 evidence is not valid JSON."); }
  if (!isF5Record(value) || Object.keys(value).some((k) => k !== "ucs_backups" && k !== "signature_updates")) {
    throw new Error("F5 evidence accepts only ucs_backups and signature_updates fields.");
  }
  if ("ucs_backups" in value) {
    const backups = value.ucs_backups;
    if (!Array.isArray(backups) || backups.length > 30 || backups.some((entry: unknown) => {
      if (!isF5Record(entry) || Object.keys(entry).length !== 2 ||
          typeof entry.name !== "string" || typeof entry.encrypted !== "boolean") return true;
      const name = entry.name;
      return name.length > 128 || !/^[a-zA-Z0-9_.\\/-]+$/.test(name) ||
        name.includes("\\\\") || name.split("/").includes("..");
    })) throw new Error("F5 UCS evidence needs up to 30 safe {name, encrypted} entries.");
  }
  if ("signature_updates" in value) {
    const update = value.signature_updates;
    if (!isF5Record(update) || Object.keys(update).length !== 2 ||
        typeof update.status !== "string" || !F5_UPDATE_STATUSES.includes(update.status) ||
        !(update.last_installed === null ||
          (typeof update.last_installed === "string" && isCalendarDate(update.last_installed)))) {
      throw new Error("F5 signature_updates requires a supported status and last_installed date or null.");
    }
  }
  const compact = JSON.stringify(value);
  if (new TextEncoder().encode(compact).length > F5_EVIDENCE_MAX_BYTES) {
    throw new Error("F5 evidence exceeds 16 KiB after normalization.");
  }
  return compact;
}

'''

OLD_SIGNATURE = 'export async function analyzeF5Phase1(file: File, signal?: AbortSignal): Promise<F5NormalizedReport> {'
NEW_SIGNATURE = 'export async function analyzeF5Phase1(file: File, signal?: AbortSignal, operatorEvidence?: File | null): Promise<F5NormalizedReport> {'
OLD_APPEND = '  form.append("file", file, file.name);'
NEW_APPEND = '''  form.append("file", file, file.name);
  if (operatorEvidence) {
    form.append("evidence_json", await readF5OperatorEvidence(operatorEvidence, signal));
  }
  if (signal?.aborted) throw new Error("F5 upload cancelled.");'''

PAGE_STATE_OLD = '  const [file, setFile] = useState<File | null>(null);'
PAGE_STATE_NEW = '''  const [file, setFile] = useState<File | null>(null);
  const [f5EvidenceFile, setF5EvidenceFile] = useState<File | null>(null);'''
PAGE_RESET_OLD = '    setFile(event.target.files?.[0] ?? null);'
PAGE_RESET_NEW = '''    setFile(event.target.files?.[0] ?? null);
    setF5EvidenceFile(null); // Do not reuse evidence with a different configuration.'''
PAGE_SWITCH_OLD = '    setChoice(platformId);'
PAGE_SWITCH_NEW = '''    setChoice(platformId);
    setF5EvidenceFile(null); // Evidence is F5-specific.'''
PAGE_CALL_OLD = 'await analyzeF5Phase1(file, controller.signal)'
PAGE_CALL_NEW = 'await analyzeF5Phase1(file, controller.signal, f5EvidenceFile)'
PAGE_CAN_OLD = 'fitsSelectedPlatform && !needsRuleChoice && !badSize;'
PAGE_CAN_NEW = '''fitsSelectedPlatform && !needsRuleChoice && !badSize &&
    (choice !== F5_PLATFORM_ID || !f5EvidenceFile ||
      (/\\.json$/i.test(f5EvidenceFile.name) && f5EvidenceFile.size > 0 && f5EvidenceFile.size <= 16384));'''
PAGE_PICKER = '''          {choice === F5_PLATFORM_ID && (
            <label className="ua-field" style={{ maxWidth: "640px" }}>
              <span>Optional F5 backup / WAF update evidence (.json)</span>
              <input type="file" accept=".json,application/json"
                onChange={(event: ChangeEvent<HTMLInputElement>) =>
                  setF5EvidenceFile(event.target.files?.[0] ?? null)}
                disabled={busy} aria-label="Choose optional F5 operator evidence JSON" />
              <span className="ua-hint">Optional metadata only, not a UCS archive. Operator claims are not independently verified.
                No credentials, backup contents, or passphrases should be included.</span>
            </label>
          )}
          {choice === F5_PLATFORM_ID && f5EvidenceFile &&
            (!/\\.json$/i.test(f5EvidenceFile.name) || f5EvidenceFile.size === 0 || f5EvidenceFile.size > 16384) && (
              <p role="alert" className="ua-alert ua-alert-error">Select a nonempty F5 evidence .json file up to 16 KiB.</p>
          )}
'''


def replace_once(src: str, old: str, new: str, label: str) -> str:
    if src.count(new) == 1 and src.count(old) == 0:
        return src
    if src.count(old) != 1 or src.count(new):
        raise ValueError(f'Unexpected {label}; stop instead of overwriting customized code')
    return src.replace(old, new, 1)


def patch_adapter(src: str) -> str:
    if src.count(NEW_SIGNATURE) == 1 and src.count(NEW_APPEND) == 1 and src.count('async function readF5OperatorEvidence(') == 1:
        return src
    if 'F5 BIG-IP (Phases 1 + 2)' not in src:
        raise ValueError('Working Phase 2 frontend adapter not found')
    src = replace_once(src, OLD_SIGNATURE, NEW_SIGNATURE, 'F5 adapter function signature')
    src = replace_once(src, OLD_APPEND, NEW_APPEND, 'F5 multipart body')
    anchor = NEW_SIGNATURE
    if src.count(anchor) != 1 or 'async function readF5OperatorEvidence(' in src:
        raise ValueError('F5 evidence helper insertion conflict')
    return src.replace(anchor, ADAPTER_HELPER + anchor, 1)


def patch_page(src: str) -> str:
    if src.count('const [f5EvidenceFile, setF5EvidenceFile]') == 1 and src.count(PAGE_CALL_NEW) == 1 and src.count('Choose optional F5 operator evidence JSON') == 1:
        return src
    if 'import { F5_PLATFORM_ID,' not in src:
        raise ValueError('Existing F5 platform selector integration missing')
    src = replace_once(src, PAGE_STATE_OLD, PAGE_STATE_NEW, 'evidence file state')
    src = replace_once(src, PAGE_RESET_OLD, PAGE_RESET_NEW, 'configuration-change reset')
    src = replace_once(src, PAGE_SWITCH_OLD, PAGE_SWITCH_NEW, 'platform-change reset')
    src = replace_once(src, PAGE_CALL_OLD, PAGE_CALL_NEW, 'F5 analysis API call')
    src = replace_once(src, PAGE_CAN_OLD, PAGE_CAN_NEW, 'upload submit validation')
    # Insert before the regular upload format hint, inside the same form.
    anchor = '          <p className="ua-hint">\n            Formats:'
    if src.count(anchor) != 1 or 'Choose optional F5 operator evidence JSON' in src:
        raise ValueError('F5 evidence picker placement not uniquely identified')
    return src.replace(anchor, PAGE_PICKER + anchor, 1)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def safe(root: Path, rel: str) -> Path:
    path = root
    for part in Path(rel).parts:
        path /= part
        if path.is_symlink():
            raise ValueError(f'Symlinks prohibited: {rel}')
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'Path escapes root: {rel}')
    return path


def decode(raw: bytes) -> tuple[str, str, bool]:
    bom = raw.startswith(b'\xef\xbb\xbf')
    text = raw.decode('utf-8-sig')
    if '\r' in text.replace('\r\n', '') or ('\r\n' in text and '\n' in text.replace('\r\n', '')):
        raise ValueError('Mixed or unsupported line endings')
    return text.replace('\r\n', '\n'), ('\r\n' if '\r\n' in text else '\n'), bom


def encode(src: str, eol: str, bom: bool) -> bytes:
    return (b'\xef\xbb\xbf' if bom else b'') + src.replace('\n', eol).encode('utf-8')


def plan(root: Path) -> dict[str, bytes]:
    root = root.resolve()
    if not safe(root, API).is_file() or not safe(root, PHASE2).is_file():
        raise ValueError('F5 Phases 1 and 2 must be installed before Phase 3')
    planned = {}
    for rel, transformer in ((ADAPTER, patch_adapter), (PAGE, patch_page)):
        f = safe(root, rel)
        if not f.is_file():
            raise ValueError(f'Required existing React file missing: {rel}')
        raw = f.read_bytes()
        src, eol, bom = decode(raw)
        updated = encode(transformer(src), eol, bom)
        if updated != raw:
            planned[rel] = updated
    if len(planned) not in (0, 2):
        raise ValueError('Partial Phase 3 integration detected; refusing unsafe installation')
    return planned


def install(root: Path, dry_run: bool = False) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    manifest = safe(root, MANIFEST)
    if manifest.exists():
        if changes:
            raise ValueError('Phase 3 manifest present but files changed; inspect manually')
        return []
    if dry_run or not changes:
        return list(changes)
    backup = safe(root, BACKUP_DIR)
    if backup.exists():
        raise ValueError('Existing Phase 3 backup directory; refusing overwrite')
    original = {rel: safe(root, rel).read_bytes() for rel in changes}
    backup.mkdir()
    written = []
    try:
        for i, rel in enumerate(FILES):
            (backup / f'{i}.bak').write_bytes(original[rel])
        for rel, data in changes.items():
            safe(root, rel).write_bytes(data)
            written.append(rel)
        manifest.write_text(json.dumps({'version': 1, 'files': [
            {'path': rel, 'original_sha256': sha(original[rel]), 'installed_sha256': sha(changes[rel]), 'backup': f'{i}.bak'}
            for i, rel in enumerate(FILES)
        ]}, indent=2), encoding='utf-8')
    except Exception:
        for rel in written:
            safe(root, rel).write_bytes(original[rel])
        for entry in backup.iterdir(): entry.unlink()
        backup.rmdir()
        manifest.unlink(missing_ok=True)
        raise
    return list(changes)


def rollback(root: Path) -> list[str]:
    root = root.resolve()
    manifest = safe(root, MANIFEST)
    if not manifest.is_file():
        raise ValueError('Phase 3 installation manifest not found')
    info = json.loads(manifest.read_text(encoding='utf-8'))
    files = info.get('files')
    if info.get('version') != 1 or not isinstance(files, list) or len(files) != 2 or {x.get('path') for x in files if isinstance(x, dict)} != set(FILES):
        raise ValueError('Invalid Phase 3 rollback manifest')
    backup = safe(root, BACKUP_DIR)
    originals = {}
    for entry in files:
        rel = entry['path']
        b = safe(root, BACKUP_DIR + '/' + entry['backup'])
        f = safe(root, rel)
        if not f.is_file() or sha(f.read_bytes()) != entry['installed_sha256'] or not b.is_file() or sha(b.read_bytes()) != entry['original_sha256']:
            raise ValueError(f'Modified file or backup after installation: {rel}')
        originals[rel] = b.read_bytes()
    for rel, content in originals.items():
        safe(root, rel).write_bytes(content)
    manifest.unlink()
    for entry in files:
        safe(root, BACKUP_DIR + '/' + entry['backup']).unlink()
    backup.rmdir()
    return list(FILES)


def main() -> int:
    ap = argparse.ArgumentParser(description='F5 Phase 3: optional operator-evidence JSON upload integration')
    ap.add_argument('root', nargs='?', default='.')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--rollback', action='store_true')
    args = ap.parse_args()
    try:
        results = rollback(Path(args.root)) if args.rollback else install(Path(args.root), args.dry_run)
        print('Rolled back:' if args.rollback else 'Would update:' if args.dry_run else 'Installed:')
        print('\n'.join('  ' + x for x in results) if results else '  No changes needed')
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
