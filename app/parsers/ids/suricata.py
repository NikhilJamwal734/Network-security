"""API-009.5: bounded static Suricata rule + selected YAML text parser.

This is NOT a general YAML parser. It recognizes a documented indentation-based
subset only, and never resolves aliases, includes, filesystem paths, or tags.
The upload boundary must validate bytes, encoding, line length and total size.
"""

from dataclasses import dataclass
import re

_ACTIONS = r"alert|drop|pass|rejectsrc|rejectdst|rejectboth|reject|log"
# Require a Suricata action followed by a supported network protocol before
# classifying an *active* line as potentially malformed rule syntax.
# A bare word such as "Log" is ordinary documentation text, not a rule.
_RULE_CANDIDATE = re.compile(
    rf"^(?:{_ACTIONS})\s+(?:tcp|udp|icmp|ip)(?=\s|$)", re.IGNORECASE
)
_RULE_HEADER = re.compile(
    rf"^(?P<action>{_ACTIONS})\s+"
    r"(?P<protocol>tcp|udp|icmp|ip)\s+"
    r"(?P<src>\S+)\s+(?P<srcport>\S+)\s+"
    r"(?P<dir>->|<>)\s+(?P<dst>\S+)\s+(?P<dstport>\S+)\s*"
    r"\((?P<options>.*)\)\s*$",
    re.IGNORECASE,
)
_YAML_KEY = re.compile(r"^([A-Za-z][\w-]{0,63}):(?:\s+(.*)|\s*)$")
_SURICATA_TOP = frozenset({
    "default-rule-path", "rule-files", "af-packet", "suricata-version",
    "vars", "outputs", "stream", "app-layer", "classification-file",
})
_YAML_TOP_STRONG = frozenset({
    "default-rule-path", "rule-files", "af-packet", "suricata-version",
})
_YAML_UNSUPPORTED = re.compile(r"(?:^|\s)(?:!{1,2}[A-Za-z]|&[A-Za-z]|\*[A-Za-z])")


@dataclass(frozen=True)
class SuricataRule:
    line_number: int
    action: str
    protocol: str
    source: str
    source_port: str
    destination: str
    destination_port: str
    sid: int | None
    gid: int | None
    revision: int | None
    enabled: bool
    option_names: tuple[str, ...]


@dataclass(frozen=True)
class SuricataConfiguration:
    rules: tuple[SuricataRule, ...]
    malformed_rule_lines: tuple[int, ...]
    home_net: str | None
    rule_file_count: int
    eve_log_enabled: bool | None
    af_packet_interfaces: int
    yaml_recognized: bool
    warnings: tuple[str, ...]


def _parts(raw: str) -> tuple[str, ...]:
    """Split rule options on unquoted semicolons (never evaluate values)."""
    fields: list[str] = []
    current: list[str] = []
    quoted = escaped = False
    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
        elif quoted and char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            quoted = not quoted
            current.append(char)
        elif char == ";" and not quoted:
            value = "".join(current).strip()
            if value:
                fields.append(value)
            current.clear()
        else:
            current.append(char)
    if quoted:
        raise ValueError("Unterminated quoted option")
    final = "".join(current).strip()
    if final:
        fields.append(final)
    return tuple(fields)


def _positive(raw: str | None, *, default: int | None = None) -> int | None:
    if raw is None:
        return default
    value = raw.strip()
    if not re.fullmatch(r"[0-9]{1,12}", value):
        return None
    number = int(value)
    return number if number > 0 else None


def _parse_rule(raw: str, number: int, enabled: bool) -> SuricataRule:
    match = _RULE_HEADER.fullmatch(raw)
    if not match:
        raise ValueError("Unsupported Suricata rule header")
    options: dict[str, str] = {}
    names: list[str] = []
    for part in _parts(match.group("options")):
        key, _, value = part.partition(":")
        key = key.strip().lower()
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", key):
            raise ValueError("Malformed Suricata rule option")
        names.append(key)
        options.setdefault(key, value.strip())
    return SuricataRule(
        line_number=number,
        action=match.group("action").lower(),
        protocol=match.group("protocol").lower(),
        source=match.group("src"),
        source_port=match.group("srcport"),
        destination=match.group("dst"),
        destination_port=match.group("dstport"),
        sid=_positive(options.get("sid")),
        gid=_positive(options.get("gid"), default=1),
        revision=_positive(options.get("rev")),
        enabled=enabled,
        option_names=tuple(names),
    )


def _scalar(raw: str) -> str:
    """Only remove simple wrapping quotes and unquoted trailing comments."""
    value = raw.strip()
    if value and value[0] in ("'", '"'):
        quote = value[0]
        end = value.find(quote, 1)
        if end > 0 and not value[end + 1:].strip().lstrip("#").strip():
            return value[1:end]
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


class SuricataParser:
    """Parse inline rules and selected literal YAML leaf values as plain text."""

    def parse(self, lines: list[str]) -> SuricataConfiguration:
        rules: list[SuricataRule] = []
        malformed: list[int] = []
        warnings: list[str] = []
        home: str | None = None
        rule_files = af_interfaces = 0
        eve: bool | None = None
        yaml_seen = False
        # Stack of (indentation, name) for the supported mapping/list subset.
        stack: list[tuple[int, str]] = []
        unrecognized_yaml = False
        for number, raw in enumerate(lines, start=1):
            text = raw.strip()
            if not text or text in ("---", "...", "%YAML 1.1"):
                continue
            if text.startswith("#"):
                # Comments are NOT executable Suricata rules. Preserve the
                # established disabled-rule inventory only when the entire
                # commented line has the shape of a real Suricata rule.
                # Importantly, comments such as "# Log the raw rule text"
                # must never create SURICATA-008 findings.
                candidate = text[1:].strip()
                if _RULE_HEADER.fullmatch(candidate):
                    try:
                        rules.append(_parse_rule(candidate, number, enabled=False))
                    except ValueError:
                        # A malformed *comment* cannot be an active failing
                        # detection rule. It remains out of scope.
                        pass
                continue
            if _RULE_CANDIDATE.match(text):
                try:
                    rules.append(_parse_rule(text, number, enabled=True))
                except ValueError:
                    malformed.append(number)
                continue
            if text.startswith(("!", "//")):
                unrecognized_yaml = True
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            if "\t" in raw[:len(raw) - len(raw.lstrip())]:
                unrecognized_yaml = True
                continue
            if _YAML_UNSUPPORTED.search(text):
                unrecognized_yaml = True
                continue
            while stack and indent <= stack[-1][0]:
                stack.pop()
            is_list = text.startswith("- ")
            content = text[2:].strip() if is_list else text
            match = _YAML_KEY.match(content)
            if match:
                key, raw_value = match.groups()
                key_lower = key.lower()
                if indent == 0 and not is_list and key_lower in _SURICATA_TOP:
                    yaml_seen = True
                # Key names are structural labels; never treated as file locations.
                parents = tuple(x[1] for x in stack)
                path = parents + (key_lower,)
                value = _scalar(raw_value or "")
                if path == ("vars", "address-groups", "home_net"):
                    home = value if value else None
                elif path == ("outputs", "eve-log", "enabled"):
                    low = value.lower()
                    if low in ("yes", "true", "on"):
                        eve = True
                    elif low in ("no", "false", "off"):
                        eve = False
                    else:
                        unrecognized_yaml = True
                elif path == ("af-packet", "interface") and value:
                    af_interfaces += 1
                stack.append((indent, key_lower))
            elif is_list:
                path = tuple(x[1] for x in stack)
                if path == ("rule-files",):
                    rule_files += 1
                elif path == ("af-packet",) and content.startswith("interface:"):
                    af_interfaces += 1
                else:
                    # Unhandled YAML list structure is not interpreted.
                    unrecognized_yaml = True
            else:
                unrecognized_yaml = True
        if rule_files:
            warnings.append("Rule-file paths were not opened; referenced rules were not assessed.")
        if malformed:
            warnings.append("Some Suricata rule-like lines could not be parsed and were not assessed.")
        if unrecognized_yaml and yaml_seen:
            warnings.append("Parts of the YAML document are outside the supported text subset; no full YAML validation was performed.")
        return SuricataConfiguration(
            rules=tuple(rules),
            malformed_rule_lines=tuple(malformed),
            home_net=home,
            rule_file_count=rule_files,
            eve_log_enabled=eve,
            af_packet_interfaces=af_interfaces,
            yaml_recognized=yaml_seen,
            warnings=tuple(warnings),
        )
