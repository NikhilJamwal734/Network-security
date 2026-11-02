
"""
Cisco ASA Parser Compatibility Module.

API-009.1 — Universal Network Security Analyzer

Maintains compatibility with existing imports:

    from app.parsers.firewalls.cisco_asa import CiscoASAParser

The original parser implementation remains at:

    app.parsers.cisco_asa

This module does not duplicate parsing logic.
"""

from app.parsers.cisco_asa import CiscoASAParser

__all__ = ["CiscoASAParser"]
