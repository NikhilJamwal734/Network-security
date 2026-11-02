"""Bounded, brace-aware reader for a supported subset of F5 BIG-IP tmsh exports.

Never executes input and never returns original configuration text. Not a complete
TMSH grammar or interpretation of inherited/system-default settings.
"""
from __future__ import annotations
from dataclasses import dataclass

SUPPORTED_TYPES = {
    ('ltm', 'profile', 'client-ssl'): 'client_ssl',
    ('ltm', 'profile', 'server-ssl'): 'server_ssl',
    ('ltm', 'profile', 'http'): 'http',
    ('ltm', 'virtual'): 'virtual',
}
MAX_TOKENS = 400_000
MAX_OBJECTS = 10_000


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    value: str
    line: int


@dataclass(frozen=True)
class ConfigObject:
    kind: str
    name: str
    line: int
    body: tuple[Token, ...]


def tokenize(source: str) -> tuple[Token, ...]:
    """F5 brace tokens, quoted atoms, # comments, escaped quotes; track lines."""
    out: list[Token] = []
    line, i, length = 1, 0, len(source)
    while i < length:
        c = source[i]
        if c in ' \t\r\n':
            if c == '\n':
                line += 1
            i += 1
            continue
        if c == '#':
            while i < length and source[i] != '\n':
                i += 1
            continue
        if c in '{}':
            out.append(Token(c, line))
            i += 1
        elif c == '"':
            start = line
            i += 1
            value: list[str] = []
            closed = False
            while i < length:
                char = source[i]
                if char == '\\' and i + 1 < length:
                    value.append(source[i + 1]); i += 2; continue
                if char == '"':
                    closed = True; i += 1; break
                if char == '\n': line += 1
                value.append(char); i += 1
            if not closed:
                raise ParseError(f'Unclosed quoted string near line {start}')
            out.append(Token(''.join(value), start))
        else:
            start = i
            while i < length and source[i] not in ' \t\r\n{}#"':
                i += 1
            out.append(Token(source[start:i], line))
        if len(out) > MAX_TOKENS:
            raise ParseError('Input contains too many configuration tokens')
    return tuple(out)


def close_index(tokens: tuple[Token, ...], opening: int) -> int:
    if tokens[opening].value != '{':
        raise ParseError('Expected opening brace')
    depth = 0
    for i in range(opening, len(tokens)):
        if tokens[i].value == '{':
            depth += 1
        elif tokens[i].value == '}':
            depth -= 1
            if depth == 0:
                return i
    raise ParseError(f'Unclosed configuration block near line {tokens[opening].line}')


def parse(source: str) -> tuple[ConfigObject, ...]:
    tokens = tokenize(source)
    result: list[ConfigObject] = []
    i = 0
    while i < len(tokens):
        match = None
        for keys, kind in SUPPORTED_TYPES.items():
            if tuple(t.value for t in tokens[i:i + len(keys)]) == keys:
                match = (kind, len(keys)); break
        if match is None:
            # Skip unrecognized top-level blocks (including iRules, not evaluated here).
            if tokens[i].value == '{':
                i = close_index(tokens, i) + 1
            else:
                i += 1
            continue
        kind, span = match
        if i + span + 1 >= len(tokens):
            raise ParseError(f'Incomplete {kind} definition near line {tokens[i].line}')
        name = tokens[i + span].value
        open_at = i + span + 1
        if tokens[open_at].value != '{':
            i += span + 1
            continue  # Not a full object definition
        end = close_index(tokens, open_at)
        result.append(ConfigObject(kind=kind, name=name, line=tokens[i].line,
                                   body=tokens[open_at + 1:end]))
        if len(result) > MAX_OBJECTS:
            raise ParseError('Too many configuration objects')
        i = end + 1
    return tuple(result)


def top_level_value(body: tuple[Token, ...], key: str) -> tuple[str, int] | None:
    """Returns a scalar appearing in the object's top-level, not a nested block."""
    depth = 0
    for i, tok in enumerate(body):
        if tok.value == '{': depth += 1; continue
        if tok.value == '}': depth -= 1; continue
        if depth == 0 and tok.value == key and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt.value not in '{}' and nxt.line == tok.line:
                return nxt.value, nxt.line
    return None


def nested_body(body: tuple[Token, ...], key: str) -> tuple[Token, ...] | None:
    depth = 0
    for i, tok in enumerate(body):
        if tok.value == '{': depth += 1; continue
        if tok.value == '}': depth -= 1; continue
        if depth == 0 and tok.value == key and i + 1 < len(body) and body[i + 1].value == '{':
            end = close_index(body, i + 1)
            return body[i + 2:end]
    return None


def list_option(body: tuple[Token, ...], key: str, option: str) -> int | None:
    nested = nested_body(body, key)
    if nested is None:
        return None
    for tok in nested:
        if tok.value == option:
            return tok.line
    return None
