"""API-009.6: conservative ASA, FortiOS, Snort 2, Suricata detection.

Shared IDS rule syntax is not sufficient for automatic identification. Only
strong, platform-specific configuration markers permit automatic IDS routing.
An explicit selection still rejects conflicting configuration markers.
"""

from dataclasses import dataclass
from enum import Enum
import re

from app.core.registry import PlatformRegistry, UnsupportedPlatformError


class DetectionStatus(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class DetectionResult:
    status: DetectionStatus
    platform_id: str | None = None
    asa_markers: int = 0
    other_markers: int = 0
    snort_markers: int = 0
    suricata_markers: int = 0
    fortios_markers: int = 0


@dataclass(frozen=True)
class PlatformSelection:
    platform_id: str
    method: str


class PlatformDetectionError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


_ASA_STRONG = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^access-list\s+\S+\s+(?:extended|standard)\s+",
    r"^object\s+(?:network|service)\s+\S+",
    r"^object-group\s+(?:network|service)\s+\S+",
    r"^access-group\s+\S+\s+(?:in|out)\s+interface\s+\S+",
    r"^nat\s*\(", r"^(?:global|static)\s*\(",
    r"^nameif\s+\S+", r"^security-level\s+\d+",
    r"^same-security-traffic\s+permit\s+",
    r"^route\s+\S+\s+\S+\s+\S+",
))
_ASA_WEAK = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^hostname\s+\S+", r"^interface\s+\S+",
))
_IDS_RULE = re.compile(
    r"^(?:alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth|sdrop|log|activate|dynamic)\s+"
    r"(?:tcp|udp|icmp|ip|http|tls|dns)\s+.+?\s+(?:->|<>)\s+.+\(",
    re.IGNORECASE,
)
_SNORT_STRONG = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^preprocessor\s+[A-Za-z_][\w]*\b",
    r"^dynamic(?:preprocessor|engine|detection)\s+",
    r"^config\s+(?:policy_mode|daq|detection|checksum_mode|event_queue)\s*:",
))
_SNORT_WEAK = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^(?:ipvar|portvar|var)\s+[A-Za-z_][\w]*\s+\S+",
    r"^include\s+\S+", r"^output\s+\S+",
))
_SURICATA_STRONG = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^(?:default-rule-path|rule-files|af-packet|suricata-version)\s*:",
))

_FORTIOS_STRONG = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^config\s+firewall\s+(?:policy|address|service\s+custom)\s*$",
    r"^config\s+system\s+interface\s*$",
))


def _active_commands(lines: list[str]):
    for raw in lines:
        text = raw.strip()
        if text and not text.startswith(("#", "!", "//")):
            yield text


def _active_with_indent(lines: list[str]):
    for raw in lines:
        text = raw.strip()
        if text and not text.startswith(("#", "!", "//")):
            yield raw, text


def detect_platform(lines: list[str], registry: PlatformRegistry) -> DetectionResult:
    asa = ids = snort = suricata = snort_weak = fortios = 0
    for raw, text in _active_with_indent(lines):
        asa_hit = any(p.match(text) for p in _ASA_STRONG)
        fortios_hit = any(p.match(text) for p in _FORTIOS_STRONG)
        rule_hit = bool(_IDS_RULE.match(text))
        strong_snort_hit = any(p.match(text) for p in _SNORT_STRONG)
        weak_snort_hit = any(p.match(text) for p in _SNORT_WEAK)
        # YAML keys qualify only at column zero, not within quoted rule options.
        strong_suricata_hit = raw == raw.lstrip(" \t") and any(
            p.match(text) for p in _SURICATA_STRONG
        )
        asa += int(asa_hit)
        fortios += int(fortios_hit)
        ids += int(rule_hit or strong_snort_hit or weak_snort_hit or strong_suricata_hit)
        snort += int(strong_snort_hit)
        snort_weak += int(weak_snort_hit)
        suricata += int(strong_suricata_hit)
    if (asa and ids) or (suricata and (snort or snort_weak)) or (
        fortios and (asa or ids)
    ):
        return DetectionResult(DetectionStatus.AMBIGUOUS, None, asa, ids, snort, suricata, fortios)
    if fortios:
        target = "fortios"
    elif asa:
        target = "cisco_asa"
    elif snort:
        target = "snort"
    elif suricata:
        target = "suricata"
    elif ids:
        return DetectionResult(DetectionStatus.UNSUPPORTED, None, asa, ids, snort, suricata, fortios)
    else:
        return DetectionResult(DetectionStatus.UNKNOWN)
    try:
        registry.get(target)
    except UnsupportedPlatformError:
        return DetectionResult(DetectionStatus.UNSUPPORTED, None, asa, ids, snort, suricata, fortios)
    return DetectionResult(DetectionStatus.SUPPORTED, target, asa, ids, snort, suricata, fortios)


def select_platform(
    lines: list[str], registry: PlatformRegistry, requested_platform: str | None = None,
) -> PlatformSelection:
    detected = detect_platform(lines, registry)
    if requested_platform is not None:
        try:
            adapter = registry.get(requested_platform)
        except (UnsupportedPlatformError, TypeError):
            raise PlatformDetectionError(
                "unsupported_platform", "Requested platform is not supported."
            ) from None
        target = adapter.descriptor.platform_id
        if detected.status is DetectionStatus.AMBIGUOUS:
            raise PlatformDetectionError(
                "ambiguous_configuration", "Configuration contains conflicting platform indicators."
            )
        if target == "cisco_asa":
            if detected.fortios_markers:
                raise PlatformDetectionError(
                    "platform_mismatch", "Configuration does not match selected Cisco ASA platform."
                )
            if detected.other_markers:
                raise PlatformDetectionError(
                    "ambiguous_configuration", "Configuration contains conflicting platform indicators."
                )
            if not detected.asa_markers and not any(
                p.match(cmd) for cmd in _active_commands(lines) for p in _ASA_WEAK
            ):
                raise PlatformDetectionError(
                    "platform_mismatch", "Configuration does not contain recognizable Cisco ASA commands."
                )
        elif target == "snort":
            if detected.asa_markers or detected.suricata_markers or detected.fortios_markers:
                raise PlatformDetectionError(
                    "platform_mismatch", "Configuration does not match the selected Snort platform."
                )
            if not detected.snort_markers and not any(
                _IDS_RULE.match(cmd) or any(p.match(cmd) for p in _SNORT_WEAK)
                for cmd in _active_commands(lines)
            ):
                raise PlatformDetectionError(
                    "platform_mismatch", "Configuration has no recognizable Snort 2 rule or directive."
                )
        elif target == "suricata":
            if detected.asa_markers or detected.snort_markers or detected.fortios_markers:
                raise PlatformDetectionError(
                    "platform_mismatch", "Configuration does not match the selected Suricata platform."
                )
            if any(
                p.match(cmd) for cmd in _active_commands(lines) for p in _SNORT_WEAK
            ):
                raise PlatformDetectionError(
                    "platform_mismatch", "Snort-style directives are not accepted as Suricata YAML."
                )
            if not detected.suricata_markers and not any(
                _IDS_RULE.match(cmd) for cmd in _active_commands(lines)
            ):
                raise PlatformDetectionError(
                    "platform_mismatch", "Configuration has no recognizable Suricata rule or YAML marker."
                )
        elif target == "fortios":
            if detected.asa_markers or detected.other_markers:
                raise PlatformDetectionError(
                    "platform_mismatch", "Configuration does not match selected FortiOS platform."
                )
            if not detected.fortios_markers:
                raise PlatformDetectionError(
                    "platform_mismatch", "No recognizable FortiOS top-level config section."
                )
        else:
            raise PlatformDetectionError(
                "unsupported_platform", "Requested platform is not supported by detection."
            )
        return PlatformSelection(target, "explicit")

    if detected.status is DetectionStatus.SUPPORTED:
        assert detected.platform_id is not None
        return PlatformSelection(detected.platform_id, "automatic")
    if detected.status is DetectionStatus.AMBIGUOUS:
        raise PlatformDetectionError(
            "ambiguous_configuration", "Configuration contains conflicting platform indicators."
        )
    if detected.status is DetectionStatus.UNSUPPORTED:
        raise PlatformDetectionError(
            "unsupported_format", "Configuration appears to use an unsupported or ambiguous platform format."
        )
    raise PlatformDetectionError(
        "unknown_format", "Unable to identify a supported platform. Select one explicitly if appropriate."
    )
