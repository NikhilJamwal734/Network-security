"""Bounded virtual-server / profile name association for F5 phase 1."""
from __future__ import annotations
from app.f5_phase1_addon.parser import ConfigObject, nested_body, close_index


def canonical(name: str, *, default_partition: str = '/Common') -> str:
    """Only resolves names in the default /Common partition when unqualified."""
    return name if name.startswith('/') else f'{default_partition}/{name}'


def profile_attachments(objects: tuple[ConfigObject, ...]) -> dict[str, list[str]]:
    """Mapping from profile full name to virtual server names (explicit refs only)."""
    refs: dict[str, list[str]] = {}
    for obj in objects:
        if obj.kind != 'virtual':
            continue
        section = nested_body(obj.body, 'profiles')
        partition = '/' + obj.name.split('/')[1] if obj.name.startswith('/') and len(obj.name.split('/')) >= 3 else '/Common'
        if section is None:
            continue
        i = 0
        while i < len(section):
            name = section[i].value
            if i + 1 < len(section) and section[i + 1].value == '{':
                end = close_index(section, i + 1)
                refs.setdefault(canonical(name, default_partition=partition), []).append(obj.name)
                i = end + 1
            elif name not in ('{', '}'):
                # Some exports list bare profile names without child blocks.
                refs.setdefault(canonical(name, default_partition=partition), []).append(obj.name)
                i += 1
            else:
                i += 1
    return refs
