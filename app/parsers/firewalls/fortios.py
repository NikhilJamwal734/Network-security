"""API-009.6: conservative, non-executing FortiOS CLI export parser.

Supported top-level blocks: firewall policy, firewall address, firewall service
custom, and system interface. Only allowlisted fields are retained. Other blocks,
secrets, VDOM nesting, reference resolution and effective-policy behavior are
outside the supported subset. This parser never executes text or opens files.
"""

from dataclasses import dataclass, field
import re
import shlex
from typing import Mapping

_SECTION_KEYS = {
    ("firewall", "policy"): frozenset({
        "name", "status", "action", "srcintf", "dstintf", "srcaddr",
        "dstaddr", "service", "schedule", "logtraffic", "nat", "utm-status",
    }),
    ("firewall", "address"): frozenset({
        "subnet", "type", "fqdn", "start-ip", "end-ip",
    }),
    ("firewall", "service", "custom"): frozenset({
        "tcp-portrange", "udp-portrange", "protocol",
    }),
    ("system", "interface"): frozenset({
        "allowaccess", "status", "ip", "role",
    }),
}
_KEY = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_MAX_DEPTH = 32
_MAX_WARNINGS = 25


@dataclass(frozen=True)
class FortiOSEntry:
    section: tuple[str, ...]
    identifier: str
    line_number: int
    values: tuple[tuple[str, tuple[str, ...]], ...]

    def get(self, key: str) -> tuple[str, ...]:
        for name, value in self.values:
            if name == key:
                return value
        return ()

    def is_set(self, key: str) -> bool:
        return any(name == key for name, _ in self.values)


@dataclass(frozen=True)
class FortiOSConfiguration:
    policies: tuple[FortiOSEntry, ...]
    addresses: tuple[FortiOSEntry, ...]
    services: tuple[FortiOSEntry, ...]
    interfaces: tuple[FortiOSEntry, ...]
    warnings: tuple[str, ...]
    malformed_lines: tuple[int, ...]


@dataclass
class _Frame:
    kind: str
    path: tuple[str, ...]
    line_number: int
    identifier: str = ""
    values: dict[str, tuple[str, ...]] = field(default_factory=dict)


def _words(raw: str) -> list[str]:
    """Tokenize *data* only. shlex.split does not interpret shell commands."""
    return shlex.split(raw, comments=False, posix=True)


class FortiOSParser:
    """Parse FortiOS `config/edit/set/next/end` blocks as bounded text."""

    def parse(self, lines: list[str]) -> FortiOSConfiguration:
        collected: dict[tuple[str, ...], list[FortiOSEntry]] = {
            path: [] for path in _SECTION_KEYS
        }
        stack: list[_Frame] = []
        warnings: list[str] = []
        malformed: list[int] = []

        def warn(number: int, message: str) -> None:
            if len(warnings) < _MAX_WARNINGS:
                warnings.append(f"Line {number}: {message}")
            malformed.append(number)

        def finish_edit() -> None:
            edit = stack.pop()
            if edit.path in collected:
                collected[edit.path].append(FortiOSEntry(
                    section=edit.path,
                    identifier=edit.identifier,
                    line_number=edit.line_number,
                    values=tuple(sorted(edit.values.items())),
                ))

        for line_number, raw in enumerate(lines, 1):
            text = raw.strip()
            if not text or text.startswith(("#", "//", "!")):
                continue
            cmd, _, tail = text.partition(" ")
            cmd = cmd.lower()
            tail = tail.strip()

            if cmd == "config":
                if not tail or len(stack) >= _MAX_DEPTH:
                    warn(line_number, "Invalid or overly nested config statement")
                    continue
                # A new config may nest within another block; nested paths do
                # not match allowlisted top-level section names.
                try:
                    words = _words(tail)
                except ValueError:
                    warn(line_number, "Invalid quoted config statement")
                    continue
                if not words or not all(_KEY.fullmatch(x.lower()) for x in words):
                    warn(line_number, "Invalid config section name")
                    continue
                path = tuple(word.lower() for word in words)
                if stack:
                    path = stack[-1].path + path
                stack.append(_Frame("config", path, line_number))
                continue

            if cmd == "edit":
                if not stack or stack[-1].kind != "config" or len(stack) >= _MAX_DEPTH:
                    warn(line_number, "edit outside a config section")
                    continue
                try:
                    words = _words(tail)
                except ValueError:
                    warn(line_number, "Invalid quoted edit identifier")
                    continue
                if len(words) != 1 or not words[0] or len(words[0]) > 128:
                    warn(line_number, "Invalid edit identifier")
                    continue
                stack.append(_Frame("edit", stack[-1].path, line_number, words[0]))
                continue

            if cmd == "set":
                if not stack or stack[-1].kind != "edit":
                    # Supported global `set` semantics are not assessed.
                    continue
                key, sep, rest = tail.partition(" ")
                key = key.lower()
                if not sep or not rest.strip() or key not in _SECTION_KEYS.get(stack[-1].path, ()):
                    continue
                try:
                    values = tuple(_words(rest.strip()))
                except ValueError:
                    warn(line_number, "Unbalanced quoted set value")
                    continue
                if values:
                    stack[-1].values[key] = values
                continue

            if cmd == "unset":
                if stack and stack[-1].kind == "edit":
                    stack[-1].values.pop(tail.lower(), None)
                continue

            if cmd == "next" and not tail:
                if stack and stack[-1].kind == "edit":
                    finish_edit()
                else:
                    warn(line_number, "next without matching edit")
                continue

            if cmd == "end" and not tail:
                if stack and stack[-1].kind == "edit":
                    warn(line_number, "edit missing next before end")
                    finish_edit()
                if stack and stack[-1].kind == "config":
                    stack.pop()
                else:
                    warn(line_number, "end without matching config")
                continue
            # Unknown FortiOS text is ignored; never interpreted as a command.

        while stack:
            frame = stack[-1]
            warn(frame.line_number, "Unclosed config or edit block")
            if frame.kind == "edit":
                finish_edit()
            else:
                stack.pop()

        return FortiOSConfiguration(
            policies=tuple(collected[("firewall", "policy")]),
            addresses=tuple(collected[("firewall", "address")]),
            services=tuple(collected[("firewall", "service", "custom")]),
            interfaces=tuple(collected[("system", "interface")]),
            warnings=tuple(warnings),
            malformed_lines=tuple(malformed),
        )
