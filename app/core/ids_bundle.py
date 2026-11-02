"""API-009.9: opt-in inspection of explicitly uploaded IDS rule files.

No filesystem lookup, include expansion, execution, YAML object construction, or
runtime policy assertion. References from configuration files are labels only.
"""

from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath
import re
from typing import Any

from app.analyzer.snort import analyze_snort_configuration
from app.analyzer.suricata import analyze_suricata_configuration
from app.parsers.ids.snort import SnortParser
from app.parsers.ids.suricata import SuricataParser

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_RULE_CHECK_CODES = {
    "snort": frozenset({"SNORT-001", "SNORT-004", "SNORT-005", "SNORT-006", "SNORT-008"}),
    "suricata": frozenset({"SURICATA-001", "SURICATA-004", "SURICATA-005", "SURICATA-006", "SURICATA-008"}),
}
_CONFIG_CHECK_CODES = {"snort": frozenset({"SNORT-003"}), "suricata": frozenset({"SURICATA-003", "SURICATA-010"})}


def _basename(value: str) -> str:
    """Treat a referenced path as inert text; never use it to open a file."""
    return PurePosixPath(value.strip().replace("\\", "/")).name.casefold()


def _references(platform: str, lines: list[str]) -> list[str]:
    references: list[str] = []
    if platform == "snort":
        for raw in lines:
            stripped = raw.strip()
            if stripped.startswith("#"):
                continue
            match = re.match(r"^include\s+(\S+)", stripped, re.IGNORECASE)
            if match and match.group(1).lower().endswith(".rules"):
                references.append(_basename(match.group(1)))
    else:
        # Recognize only top-level literal rule-files list entries.
        in_rule_files = False
        top_indent = -1
        for raw in lines:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            if in_rule_files and indent <= top_indent:
                in_rule_files = False
            if indent == 0 and stripped == "rule-files:":
                in_rule_files = True
                top_indent = indent
                continue
            if in_rule_files and stripped.startswith("- "):
                entry = stripped[2:].split(" #", 1)[0].strip().strip("\"'")
                if entry.lower().endswith(".rules") and len(entry) <= 250:
                    references.append(_basename(entry))
    # Preserve duplicates in the config, because duplicates can be meaningful.
    return references


def analyze_ids_rule_bundle(
    *, platform: str, rule_files: list[tuple[str, list[str]]],
    config: tuple[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Analyze a bounded set of **already validated** user-supplied text lines.

    The API boundary handles all file limits. This function never opens paths.
    """
    if platform not in ("snort", "suricata"):
        raise ValueError("Only Snort and Suricata rules can be bundled")
    if not rule_files:
        raise ValueError("At least one uploaded .rules file is required")

    parser = SnortParser() if platform == "snort" else SuricataParser()
    analyzer = analyze_snort_configuration if platform == "snort" else analyze_suricata_configuration
    sources = ([config] if config is not None else []) + rule_files
    seen_ids: dict[tuple[int, ...], tuple[str, int]] = {}
    results: list[dict[str, Any]] = []
    inventory: list[dict[str, Any]] = []
    warnings: list[str] = []
    files_with_malformed = 0
    total_enabled = total_disabled = 0

    for filename, lines in sources:
        parsed = parser.parse(lines)
        is_config = config is not None and filename == config[0]
        selected_checks = _RULE_CHECK_CODES[platform] | (_CONFIG_CHECK_CODES[platform] if is_config else frozenset())
        for item in analyzer(parsed):
            if item["code"] not in selected_checks:
                continue
            # The earlier Snort 2 subset flags some commented documentation
            # with a rule action word as malformed. Comments are never active
            # rule failures, so exclude those from bundle security findings.
            if item["code"] == "SNORT-008" and isinstance(item.get("line_number"), int):
                number = item["line_number"]
                if 1 <= number <= len(lines) and lines[number - 1].lstrip().startswith("#"):
                    continue
            results.append({
                "code": item["code"],
                "severity": item["severity"].lower(),
                "title": item["title"],
                "description": item["description"],
                "recommendation": item["recommendation"],
                "evidence": {"filename": filename, "line_number": item.get("line_number"), "sid": item.get("rule_id")},
            })
        active = sum(rule.enabled for rule in parsed.rules)
        disabled = len(parsed.rules) - active
        total_enabled += active
        total_disabled += disabled
        files_with_malformed += bool(parsed.malformed_rule_lines)
        inventory.append({
            "filename": filename,
            "kind": "configuration" if is_config else "rules",
            "parsed_rules": len(parsed.rules),
            "active_rules": active,
            "disabled_rules": disabled,
            "unparsed_active_rule_lines": len(parsed.malformed_rule_lines),
        })

        for rule in parsed.rules:
            if not rule.enabled or rule.sid is None:
                continue
            if platform == "suricata":
                if rule.gid is None:
                    continue
                identity = (rule.gid, rule.sid)
            else:
                identity = (rule.sid,)
            first = seen_ids.get(identity)
            if first:
                results.append({
                    "code": "IDS-BUNDLE-001",
                    "severity": "high",
                    "title": "Duplicate enabled rule identifier across uploaded sources",
                    "description": (
                        "The same enabled rule identifier appears more than once in the "
                        "uploaded text sources. This does not establish which rules are loaded at runtime."
                    ),
                    "recommendation": "Resolve repeated enabled (GID, SID) or SID identities and validate the intended ruleset with the IDS engine.",
                    "evidence": {"filename": filename, "line_number": rule.line_number,
                                 "sid": rule.sid, "gid": identity[0] if platform == "suricata" else None,
                                 "related_filename": first[0], "related_line_number": first[1]},
                })
            else:
                seen_ids[identity] = (filename, rule.line_number)

    references = _references(platform, config[1]) if config else []
    uploaded_names = {_basename(name) for name, _ in rule_files}
    matched = sum(name in uploaded_names for name in references)
    unmatched = len(references) - matched
    if config is None:
        warnings.append("No main IDS configuration was supplied; effective includes and output settings were not assessed.")
    if references:
        warnings.append("Reference matches use filenames only; path identity and effective rule loading were not verified.")
    if unmatched:
        warnings.append("Some referenced rule files were not supplied for inspection.")
    if files_with_malformed:
        warnings.append("Some active rule-like lines were not parsed by the supported syntax subset.")
    counts = Counter(item["severity"] for item in results)
    return {
        "schema_version": "1.0",
        "platform": {"platform_id": platform, "family": "ids", "detection_method": "explicit"},
        "summary": {
            "total_findings": len(results),
            "severity_counts": {key: counts[key] for key in SEVERITIES},
            "files_inspected": len(inventory),
            "rule_files_uploaded": len(rule_files),
            "enabled_rules_visible": total_enabled,
            "disabled_rules_visible": total_disabled,
            "security_score": None,
        },
        "files": inventory,
        "findings": results,
        "coverage": {
            "uploaded_rule_text": "assessed_subset",
            "referenced_files": {
                "entries_visible": len(references),
                "filename_candidate_matches": matched,
                "not_uploaded": unmatched,
                "identity_verified": False,
            },
            "effective_loaded_rules": "not_assessed",
            "runtime_detection": "not_assessed",
            "full_rule_grammar": "not_assessed",
        },
        "warnings": warnings,
        "notice": (
            "Only explicitly uploaded text was examined. Filename matches do not prove a rule file "
            "is the one Suricata or Snort loads. No referenced path was followed. "
            "No numeric security score or runtime assurance is provided."
        ),
    }
