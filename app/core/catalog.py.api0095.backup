"""Application-controlled, opt-in registry: no dynamic adapter loading from input."""

from app.core.adapters.cisco_asa import CiscoASAAdapter
from app.core.adapters.fortios import FortiOSAdapter
from app.core.adapters.snort import SnortAdapter
from app.core.adapters.suricata import SuricataAdapter
from app.core.registry import PlatformRegistry


def create_default_registry() -> PlatformRegistry:
    registry = PlatformRegistry()
    registry.register(CiscoASAAdapter())
    registry.register(FortiOSAdapter())
    registry.register(SnortAdapter())
    registry.register(SuricataAdapter())
    return registry
