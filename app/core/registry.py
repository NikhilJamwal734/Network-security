"""Explicit, opt-in registry of supported configuration platform adapters."""

from .platforms import PlatformAdapter, PlatformDescriptor


class UnsupportedPlatformError(LookupError):
    """The platform has no explicitly registered analyzer."""


class PlatformRegistry:
    """Store trusted adapters; never load classes from uploaded files."""

    def __init__(self) -> None:
        self._adapters: dict[str, PlatformAdapter] = {}

    def register(self, adapter: PlatformAdapter) -> None:
        descriptor = getattr(adapter, "descriptor", None)
        if not isinstance(descriptor, PlatformDescriptor):
            raise TypeError("adapter.descriptor must be a PlatformDescriptor")
        if not callable(getattr(adapter, "analyze", None)):
            raise TypeError("adapter must provide an analyze(lines) method")
        key = descriptor.platform_id
        if key in self._adapters:
            raise ValueError(f"platform already registered: {key}")
        self._adapters[key] = adapter

    def get(self, platform_id: str) -> PlatformAdapter:
        if not isinstance(platform_id, str):
            raise TypeError("platform_id must be a string")
        key = platform_id.strip().lower()
        try:
            return self._adapters[key]
        except KeyError:
            raise UnsupportedPlatformError(
                f"Unsupported platform: {platform_id!r}"
            ) from None

    def list_platforms(self) -> tuple[PlatformDescriptor, ...]:
        """Return immutable metadata sorted by platform identifier."""
        return tuple(
            self._adapters[key].descriptor for key in sorted(self._adapters)
        )
