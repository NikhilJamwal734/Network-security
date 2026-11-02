"""API-010.2: context-sensitive refinement of API-010.1 supplemental checks.

Conservative and non-executing. Does not affect normalized findings, risk level,
severity counts, or provisional score. Unknown device semantics remain unknown.
This deliberately does not claim effective packet reachability.
"""
from __future__ import annotations

from collections import Counter
import ipaddress
from typing import Any

from app.parsers.firewalls.fortios import FortiOSParser
from app.parsers.ids.snort import SnortParser
from app.parsers.ids.suricata import SuricataParser

MAX_CHECKS = 40


def _check(code: str, severity: str, title: str, detail: str,
           recommendation: str, line_number: int | None, rule_id: str | int | None = None) -> dict[str, Any]:
    return {
        "code": code, "severity": severity, "title": title, "detail": detail,
        "recommendation": recommendation, "line_number": line_number,
        "rule_id": rule_id,
    }


def _key(item: dict[str, Any]) -> tuple[str, int | None, str | int | None]:
    return (item["code"], item["line_number"], item["rule_id"])


def _asa(lines: list[str], original: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Last explicit action for identical ASA selectors and logging enablement."""
    entries: dict[tuple[str, str, str, str], tuple[bool, int]] = {}
    logging: tuple[bool, int] | None = None
    for n, raw in enumerate(lines, 1):
        s = raw.strip().lower()
        if not s or s.startswith(("#", "!")):
            continue
        parts = s.split()
        if parts == ["logging", "enable"]:
            logging = (True, n)
        elif parts == ["no", "logging", "enable"]:
            logging = (False, n)
        negation = bool(parts and parts[0] == "no")
        tokens = parts[1:] if negation else parts
        if len(tokens) != 4 or tokens[0] not in ("ssh", "telnet"):
            continue
        try:
            src = ipaddress.IPv4Address(tokens[1])
            mask = ipaddress.IPv4Address(tokens[2])
        except ipaddress.AddressValueError:
            continue
        if int(src) != 0 or int(mask) != 0:
            continue
        entries[tuple(tokens)] = (not negation, n)
    result = [x for x in original if x["code"] not in ("ASA-DEEP-001", "ASA-DEEP-002", "ASA-DEEP-003")]
    for parts, (enabled, n) in entries.items():
        if not enabled:
            continue
        if parts[0] == "telnet":
            result.append(_check("ASA-DEEP-001", "HIGH", "Unrestricted Telnet management selector",
                "The last visible action for this Telnet selector permits all IPv4 sources. Actual interface reachability is unverified.",
                "Disable Telnet where possible and restrict management sources.", n))
        else:
            result.append(_check("ASA-DEEP-002", "MEDIUM", "Unrestricted SSH management selector",
                "The last visible action for this SSH selector permits all IPv4 sources. ACL and routing effects are unknown.",
                "Restrict SSH to approved administrator networks and verify effective access.", n))
    if logging is not None and not logging[0]:
        result.append(_check("ASA-DEEP-003", "MEDIUM", "ASA logging explicitly disabled",
            "The last visible global logging enablement directive disables logging. Other telemetry mechanisms are not assessed.",
            "Review logging policy and enable the required device telemetry.", logging[1]))
    return result, [
        "Only identical IPv4 management-selector negations and the last global logging directive are resolved.",
        "Non-identical management entries, configuration contexts, ACLs, NAT, routing and operational state are not simulated.",
    ]


def _fortios(lines: list[str], original: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    conf = FortiOSParser().parse(lines)
    collections = (conf.policies, conf.interfaces, conf.services)
    repeated = [set() for _ in collections]
    for i, seq in enumerate(collections):
        counts = Counter(entry.identifier for entry in seq)
        repeated[i] = {name for name, count in counts.items() if count > 1}
    # Multiple edits may contain partial field updates. Avoid presenting a
    # stale observation as effective for an identifier with ambiguous edits.
    codes = (
        {"FORTIOS-DEEP-001"},
        {"FORTIOS-DEEP-002"},
        {"FORTIOS-DEEP-003"},
    )
    filtered: list[dict[str, Any]] = []
    for item in original:
        ambiguous = any(item["code"] in code_group and str(item["rule_id"]) in repeated[i]
                        for i, code_group in enumerate(codes))
        if not ambiguous:
            filtered.append(item)
    for policy in conf.policies:
        if policy.identifier in repeated[0]:
            continue
        if "accept" not in {s.lower() for s in policy.get("action")}:
            continue
        if "disable" in {s.lower() for s in policy.get("status")}:
            continue
        if "disable" in {s.lower() for s in policy.get("logtraffic")}:
            filtered.append(_check("FORTIOS-PREC-001", "LOW", "Policy logging explicitly disabled",
                "An enabled accept policy explicitly sets logtraffic to disable. Global telemetry and logging of other policies are unknown.",
                "Verify whether this policy requires traffic logging and enable it if required.", policy.line_number, policy.identifier))
    for interface in conf.interfaces:
        if interface.identifier in repeated[1]:
            continue
        if "wan" not in {s.lower() for s in interface.get("role")}:
            continue
        if "down" in {s.lower() for s in interface.get("status")}:
            continue
        protocols = {s.lower() for s in interface.get("allowaccess")}
        if protocols.intersection({"http", "telnet"}):
            filtered.append(_check("FORTIOS-PREC-002", "HIGH", "Cleartext management permitted on WAN-role interface",
                "The interface is explicitly role=wan and allows HTTP or Telnet management. WAN role is not proof of public reachability.",
                "Disable cleartext management where possible; verify local-in and trusted-host controls.",
                interface.line_number, interface.identifier))
    limits = [
        "Repeated FortiOS edit IDs are excluded from this review where partial updates could make parsed values stale.",
        "No policy ordering, VDOM, group expansion, local-in rules, default resolution or actual interface exposure is evaluated.",
    ]
    return filtered, limits


def _snort(lines: list[str], original: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    conf = SnortParser().parse(lines)
    first: dict[int, int] = {}
    result = original[:]
    seen: set[int] = set()
    for rule in conf.rules:
        if not rule.enabled or rule.sid is None:
            continue
        if rule.sid in first and rule.sid not in seen:
            seen.add(rule.sid)
            result.append(_check("SNORT-PREC-001", "MEDIUM", "Duplicate enabled Snort SID",
                "Two enabled, parsed rules declare the same SID in the uploaded text. Generator ID and include-file resolution were not assessed.",
                "Check rule identifiers and inspect the complete deployed rule set.", rule.line_number, rule.sid))
        first.setdefault(rule.sid, rule.line_number)
    return result, [
        "Duplicate SID checks consider only parsed enabled rules in this uploaded text; Snort generator IDs are not resolved.",
        "Includes, Snort 3 Lua, multiline rules, variables and runtime activation are not evaluated.",
    ]


def _suricata(lines: list[str], original: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    conf = SuricataParser().parse(lines)
    first: dict[tuple[int, int], int] = {}
    reported: set[tuple[int, int]] = set()
    result = original[:]
    for rule in conf.rules:
        if not rule.enabled or rule.sid is None or rule.gid is None:
            continue
        key = (rule.gid, rule.sid)
        if key in first and key not in reported:
            reported.add(key)
            result.append(_check("SURICATA-PREC-001", "MEDIUM", "Duplicate enabled Suricata GID/SID",
                "Two enabled parsed rules in the uploaded text use the same GID/SID pair. External rule files were not loaded.",
                "Review the complete rule inventory and resolve unintended duplicate identifiers.", rule.line_number, f"{rule.gid}:{rule.sid}"))
        first.setdefault(key, rule.line_number)
    return result, [
        "Only exact GID/SID pairs from supported enabled rule syntax are compared; commented-out rules are ignored.",
        "Referenced rule files, YAML aliases/includes and effective Suricata execution mode are not assessed.",
    ]


_DISPATCH = {
    "cisco_asa": _asa,
    "fortios": _fortios,
    "snort": _snort,
    "suricata": _suricata,
}


def refine_vendor_review(platform: str, lines: list[str], review: dict[str, Any]) -> dict[str, Any]:
    """Return a separate refined review; do not mutate API-010.1's original."""
    if platform not in _DISPATCH:
        raise ValueError("Unsupported precision review platform")
    old_checks = review.get("checks", [])
    if not isinstance(old_checks, list):
        raise ValueError("Invalid preliminary review")
    current, caveats = _DISPATCH[platform](lines, old_checks)
    unique: dict[tuple[str, int | None, str | int | None], dict[str, Any]] = {}
    for item in current:
        unique.setdefault(_key(item), item)
    refined = list(unique.values())
    old_keys = {_key(c) for c in old_checks}
    new_keys = set(unique)
    corrections = len(old_keys - new_keys)
    additions = len(new_keys - old_keys)
    # Reconstruct original response fields without altering original score model.
    result = dict(review)
    result["checks"] = refined[:MAX_CHECKS]
    result["suppressed_checks"] = int(review.get("suppressed_checks", 0)) + max(0, len(refined) - MAX_CHECKS)
    result["limitations"] = list(review.get("limitations", [])) + caveats
    result["precision"] = {
        "version": "1.0",
        "status": "context_refined",
        "suppressed_preliminary_checks": corrections,
        "additional_evidence_checks": additions,
        "note": "Source-context refinement is limited to supported syntax. Neither a zero-check result nor a consistent configuration guarantees security.",
    }
    from app.core.precision_enhancements import augment_precision_review
    return augment_precision_review(platform, lines, result)
