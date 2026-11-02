"""Snort 2-style IDS rule/config parser for static, untrusted text.

No include files are opened; no rule expressions are compiled or executed.
Only a documented subset of Snort 2 text syntax is recognized. Snort 3 Lua
configuration, rule continuations, and dynamically loaded rules are NOT parsed.
"""

from dataclasses import dataclass, field
import re

_ACTIONS = r"alert|log|pass|drop|reject|sdrop|activate|dynamic"
_RULE_START = re.compile(rf"^(?:{_ACTIONS})\s+", re.IGNORECASE)
_HEADER = re.compile(
    rf"^(?P<action>{_ACTIONS})\s+"
    r"(?P<protocol>tcp|udp|icmp|ip)\s+"
    r"(?P<source>\S+)\s+(?P<source_port>\S+)\s+"
    r"(?P<direction>->|<>)\s+(?P<destination>\S+)\s+"
    r"(?P<destination_port>\S+)\s*\((?P<options>.*)\)\s*$",
    re.IGNORECASE,
)
_VARIABLE = re.compile(
    r"^(?:ipvar|portvar|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$",
    re.IGNORECASE,
)
_INCLUDE = re.compile(r"^include\s+\S+", re.IGNORECASE)
_OUTPUT = re.compile(r"^output\s+\S+", re.IGNORECASE)
_CONFIG = re.compile(r"^(?:config|preprocessor|dynamicpreprocessor|dynamicengine|dynamicdetection)\s+", re.IGNORECASE)


@dataclass(frozen=True)
class SnortRule:
    line_number: int
    action: str
    protocol: str
    source: str
    source_port: str
    direction: str
    destination: str
    destination_port: str
    sid: int | None
    revision: int | None
    message: str | None
    option_names: tuple[str, ...]
    enabled: bool


@dataclass(frozen=True)
class SnortConfiguration:
    rules: tuple[SnortRule, ...]
    variables: dict[str, str]
    includes_count: int
    output_directives_count: int
    malformed_rule_lines: tuple[int, ...]
    warnings: tuple[str, ...]
    saw_snort_config: bool


def _split_options(text: str) -> tuple[str, ...]:
    """Split on semicolons outside double quotes; never evaluate contents."""
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quoted:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
        if char == ";" and not quoted:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current.clear()
            continue
        current.append(char)
    if quoted:
        raise ValueError("Unterminated quoted rule option")
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return tuple(parts)


def _parse_positive_integer(value: str | None) -> int | None:
    if value is None or not re.fullmatch(r"[0-9]{1,12}", value.strip()):
        return None
    number = int(value)
    return number if number > 0 else None


def _parse_rule(line: str, line_number: int, enabled: bool) -> SnortRule:
    match = _HEADER.fullmatch(line)
    if match is None:
        raise ValueError("Unsupported or malformed Snort rule header")
    options = _split_options(match.group("options"))
    parsed: dict[str, str] = {}
    option_names: list[str] = []
    for part in options:
        key, _, value = part.partition(":")
        key = key.strip().lower()
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", key):
            raise ValueError("Malformed Snort rule option")
        option_names.append(key)
        parsed.setdefault(key, value.strip())

    raw_msg = parsed.get("msg")
    message = None
    if raw_msg is not None:
        message = raw_msg[1:-1] if raw_msg.startswith('"') and raw_msg.endswith('"') else raw_msg

    return SnortRule(
        line_number=line_number,
        action=match.group("action").lower(),
        protocol=match.group("protocol").lower(),
        source=match.group("source"),
        source_port=match.group("source_port"),
        direction=match.group("direction"),
        destination=match.group("destination"),
        destination_port=match.group("destination_port"),
        sid=_parse_positive_integer(parsed.get("sid")),
        revision=_parse_positive_integer(parsed.get("rev")),
        message=message,
        option_names=tuple(option_names),
        enabled=enabled,
    )


class SnortParser:
    """Read a restricted Snort 2 configuration/rules subset, without side effects."""

    def parse(self, lines: list[str]) -> SnortConfiguration:
        rules: list[SnortRule] = []
        variables: dict[str, str] = {}
        malformed: list[int] = []
        warnings: list[str] = []
        includes = 0
        outputs = 0
        saw_snort_config = False

        for number, raw in enumerate(lines, start=1):
            text = raw.strip()
            if not text:
                continue
            enabled = True
            if text.startswith("#"):
                # Commented-out rules may be reported as disabled.
                possible_rule = text[1:].strip()
                if not _RULE_START.match(possible_rule):
                    continue
                enabled = False
                text = possible_rule
            if text.startswith(("//", "!")):
                continue
            if _RULE_START.match(text):
                try:
                    rules.append(_parse_rule(text, number, enabled))
                except ValueError:
                    malformed.append(number)
                continue
            var = _VARIABLE.fullmatch(text)
            if var:
                key, value = var.groups()
                if key.upper() in variables:
                    warnings.append(f"Network variable redefined at line {number}.")
                variables[key.upper()] = value.strip()
                saw_snort_config = True
                continue
            if _INCLUDE.match(text):
                includes += 1
                saw_snort_config = True
                continue
            if _OUTPUT.match(text):
                outputs += 1
                saw_snort_config = True
                continue
            if _CONFIG.match(text):
                saw_snort_config = True
                continue
            # Unknown directives are left uninterpreted, not executed.
            # Recording a count would be a future coverage enhancement.

        if includes:
            warnings.append(
                "Include directives were not followed; referenced rule files were not inspected."
            )
        if malformed:
            warnings.append(
                "Some rule-like lines could not be parsed; those lines were not assessed."
            )
        return SnortConfiguration(
            rules=tuple(rules),
            variables=variables,
            includes_count=includes,
            output_directives_count=outputs,
            malformed_rule_lines=tuple(malformed),
            warnings=tuple(warnings),
            saw_snort_config=saw_snort_config,
        )
