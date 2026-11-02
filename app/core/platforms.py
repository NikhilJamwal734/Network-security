"""Metadata and interfaces shared by firewall, IDS, and IPS adapters.

Uploaded configurations are untrusted input. Adapter registration is entirely
application-controlled; a configuration file cannot register a plugin.
"""

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Protocol, TypeVar


_PLATFORM_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class DeviceFamily(str, Enum):
    FIREWALL = "firewall"
    IDS = "ids"
    IPS = "ips"


@dataclass(frozen=True)
class PlatformDescriptor:
    """Immutable catalog information, not untrusted parsed file content."""

    platform_id: str
    display_name: str
    family: DeviceFamily
    extensions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _PLATFORM_ID_PATTERN.fullmatch(self.platform_id):
            raise ValueError("platform_id must be lowercase snake_case (max 64 chars)")
        if not self.display_name.strip():
            raise ValueError("display_name cannot be blank")
        if not isinstance(self.family, DeviceFamily):
            raise TypeError("family must be a DeviceFamily")
        if not self.extensions:
            raise ValueError("at least one extension is required")
        for extension in self.extensions:
            if not re.fullmatch(r"\.[a-z0-9]{1,12}", extension):
                raise ValueError("extensions must be lowercase file suffixes")


ParsedConfigT = TypeVar("ParsedConfigT", covariant=True)


class ConfigurationParser(Protocol[ParsedConfigT]):
    """Structural contract for vendor-specific parsers.

    A parser receives decoded lines and returns a vendor-specific object.
    The public upload boundary remains responsible for validation.
    """

    def parse(self, lines: list[str]) -> ParsedConfigT:
        ...


class PlatformAdapter(Protocol):
    """A supported platform's parser + analyzer + serializer boundary.

    Inputs are already decoded and validated by the existing upload endpoint.
    Implementations must treat every line as data; do not execute file content.

    API-009.1 maintains the current Cisco ASA API response shape. A common
    cross-platform output schema will be introduced in API-009.3.
    """

    descriptor: PlatformDescriptor

    def analyze(self, lines: list[str]) -> dict[str, Any]:
        """Analyze configuration lines and return a JSON-compatible report."""
        ...
