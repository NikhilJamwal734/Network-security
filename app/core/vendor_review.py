"""API-010.1: conservative vendor-specific supplemental static checks.

Never execute configurations or open referenced files. These observations do
not enter the normalized findings, severity totals, or provisional score.
Only explicit settings or fully parsed, enabled rule headers may produce a check.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

MAX_CHECKS = 40
_RULE_CONSTRAINTS = frozenset({
    "content", "pcre", "dsize", "flow", "flowbits", "flowint",
    "byte_test", "byte_jump", "byte_extract", "threshold", "detection_filter",
    "stream_size", "isdataat", "flags", "ack", "seq", "window", "itype",
    "icode", "ttl", "tos", "ip_id", "fragbits", "fragoffset", "app-layer-protocol",
})


def _review(platform: str, checks: list[dict[str, Any]], limits: list[str]) -> dict[str, Any]:
    return {
        "version": "1.0",
        "platform_id": platform,
        "scope": "supplemental_vendor_specific_static_review",
        "checks": checks[:MAX_CHECKS],
        "suppressed_checks": max(0, len(checks) - MAX_CHECKS),
        "limitations": limits,
        "interpretation": (
            "These are additional, evidence-backed configuration observations, not a "
            "verified exploit or runtime security verdict. They are not included in the "
            "existing finding counts or provisional review score."
        ),
    }


def _add(checks: list[dict[str, Any]], code: str, severity: str, title: str,
         detail: str, recommendation: str, line_number: int | None,
         rule_id: str | int | None = None) -> None:
    # Bound computation and response size even for large uploads.
    if len(checks) >= MAX_CHECKS + 1:
        return
    checks.append({
        "code": code, "severity": severity, "title": title,
        "detail": detail, "recommendation": recommendation,
        "line_number": line_number, "rule_id": rule_id,
    })


def _all_ipv4(value: str) -> bool:
    candidate = value.strip().strip('"\'')
    if candidate.casefold() == "any":
        return True
    if candidate in ("0.0.0.0/0", "[0.0.0.0/0]", "{0.0.0.0/0}"):
        return True
    try:
        return ipaddress.ip_network(candidate, strict=False).prefixlen == 0
    except ValueError:
        return False


def review_cisco_asa(lines: list[str]) -> dict[str, Any]:
    """Analyze only explicit ASA management directives; no ACL reachability assumptions."""
    checks: list[dict[str, Any]] = []
    for n, raw in enumerate(lines, 1):
        text = raw.strip()
        if not text or text.startswith(("!", "#")):
            continue
        parts = text.lower().split()
        if len(parts) == 4 and parts[0] in ("telnet", "ssh"):
            # ASA command shape: telnet|ssh <source> <mask> <interface>.
            try:
                source = ipaddress.IPv4Address(parts[1])
                mask = ipaddress.IPv4Address(parts[2])
            except ipaddress.AddressValueError:
                continue
            if int(source) == 0 and int(mask) == 0:
                if parts[0] == "telnet":
                    _add(checks, "ASA-DEEP-001", "HIGH", "Unrestricted Telnet management selector",
                         "The explicit Telnet management entry uses 0.0.0.0 0.0.0.0 as its permitted source. Whether it is reachable is not established.",
                         "Disable Telnet where possible; restrict management sources and verify interface reachability.", n)
                else:
                    _add(checks, "ASA-DEEP-002", "MEDIUM", "Unrestricted SSH management selector",
                         "The explicit SSH management entry selects all IPv4 sources; interface ACLs and reachability were not assessed.",
                         "Restrict SSH management to approved administrative source networks.", n)
        if parts == ["no", "logging", "enable"]:
            _add(checks, "ASA-DEEP-003", "MEDIUM", "ASA logging explicitly disabled",
                 "The uploaded configuration explicitly contains 'no logging enable'; this does not establish remote logging state elsewhere.",
                 "Confirm the intended logging architecture and enable the relevant device logging settings.", n)
    return _review("cisco_asa", checks, [
        "ASA command matching is limited to explicit management source selectors and logging disablement.",
        "ACL expansion, interfaces, NAT, routing, context mode, and runtime reachability were not evaluated by these extra checks.",
    ])


def review_fortios(config: Any) -> dict[str, Any]:
    """Inspect FortiOS allowlisted, parsed policies, interfaces and services."""
    checks: list[dict[str, Any]] = []
    for policy in config.policies:
        if "disable" in (s.casefold() for s in policy.get("status")):
            continue
        if "accept" not in (s.casefold() for s in policy.get("action")):
            continue
        src = {s.casefold() for s in policy.get("srcaddr")}
        dst = {s.casefold() for s in policy.get("dstaddr")}
        services = {s.casefold() for s in policy.get("service")}
        if "all" in src and "all" in dst and "all" not in services and services:
            _add(checks, "FORTIOS-DEEP-001", "MEDIUM", "Broad policy address selectors",
                 "An enabled accept policy explicitly uses all source and destination addresses, although its service selection is narrower than ALL. Interface, schedule and policy-order limits remain unknown.",
                 "Review address scope and confirm only intended source and destination networks are allowed.",
                 policy.line_number, policy.identifier)
    for interface in config.interfaces:
        if "down" in (s.casefold() for s in interface.get("status")):
            continue
        if "wan" not in (s.casefold() for s in interface.get("role")):
            continue
        enabled = {s.casefold() for s in interface.get("allowaccess")}
        secure_mgmt = sorted(enabled.intersection({"ssh", "https"}))
        if secure_mgmt:
            _add(checks, "FORTIOS-DEEP-002", "MEDIUM", "Management service on WAN-role interface",
                 f"The interface is explicitly marked role=wan and permits {', '.join(secure_mgmt)} management access. Actual public exposure is unverified.",
                 "Verify trusted-host restrictions, local-in policy, source networks and remote-management intent.",
                 interface.line_number, interface.identifier)
    for service in config.services:
        for key in ("tcp-portrange", "udp-portrange"):
            if any(v in ("0-65535", "1-65535") for v in service.get(key)):
                _add(checks, "FORTIOS-DEEP-003", "LOW", "Custom service spans almost all ports",
                     f"Custom service explicitly defines {key} covering nearly all ports. Its policy references were not resolved.",
                     "Review whether the custom service needs its entire declared port range.",
                     service.line_number, service.identifier)
                break
    return _review("fortios", checks, [
        "Only explicitly selected CLI fields are inspected; defaults, policy groups, VDOMs and resolution are not supported.",
        "A WAN-role interface is not proof of Internet exposure, and port-wide services may be unused.",
    ])


def _unrestricted_header(rule: Any) -> bool:
    return all(str(getattr(rule, key, "")).casefold() == "any" for key in
               ("source", "source_port", "destination", "destination_port"))


def _has_common_constraints(rule: Any) -> bool:
    return bool(set(rule.option_names).intersection(_RULE_CONSTRAINTS))


def review_snort(config: Any) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for rule in config.rules:
        if not rule.enabled:
            continue
        if rule.action in ("drop", "reject", "sdrop") and _unrestricted_header(rule) and not _has_common_constraints(rule):
            _add(checks, "SNORT-DEEP-001", "MEDIUM", "Unrestricted inline blocking rule header",
                 "An enabled drop/reject rule matches any-to-any addresses and ports and has none of the commonly recognized restrictive options in this subset. The deployment mode and full semantics are unknown.",
                 "Review action, matching conditions and the actual inline deployment before enforcing this rule.",
                 rule.line_number, rule.sid)
    home = config.variables.get("HOME_NET")
    if isinstance(home, str) and _all_ipv4(home) and home.casefold().strip() != "any":
        _add(checks, "SNORT-DEEP-002", "HIGH", "HOME_NET covers all IPv4 networks",
             "The visible HOME_NET value uses the universal IPv4 prefix, which does not scope detection to protected subnets.",
             "Restrict HOME_NET to the intended protected networks where appropriate.", None)
    return _review("snort", checks, [
        "Only supported Snort 2 rule headers and simple variable declarations are inspected.",
        "Included rules, preprocessors, Snort 3 Lua configuration and runtime inline mode were not evaluated.",
    ])


def review_suricata(config: Any) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for rule in config.rules:
        if not rule.enabled:
            continue
        if rule.action in ("drop", "reject", "rejectsrc", "rejectdst", "rejectboth") and _unrestricted_header(rule) and not _has_common_constraints(rule):
            _add(checks, "SURICATA-DEEP-001", "MEDIUM", "Unrestricted inline blocking rule header",
                 "An enabled drop/reject rule has any-to-any address/port selectors without commonly recognized constraints in this subset. Actual IPS deployment is unverified.",
                 "Review the rule and validate intended enforcement using the deployed Suricata rule-set.",
                 rule.line_number, rule.sid)
    home = config.home_net
    if isinstance(home, str) and _all_ipv4(home) and home.casefold().strip() != "any":
        _add(checks, "SURICATA-DEEP-002", "HIGH", "HOME_NET uses the universal IPv4 prefix",
             "The visible HOME_NET value contains 0.0.0.0/0, so it is not restricted to a protected subnet.",
             "Review the configured protected address group in the effective YAML.", None)
    return _review("suricata", checks, [
        "Only rule lines and a limited Suricata YAML subset are inspected.",
        "YAML aliases, included rule files, flow evaluation and real IPS deployment were not evaluated.",
    ])
