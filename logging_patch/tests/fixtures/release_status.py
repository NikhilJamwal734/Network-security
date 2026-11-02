"""Minimal API-012.0 installation status; not an external readiness attestation.

No host paths, runtime configuration, dependency versions, or secrets are exposed.
"""
from fastapi import APIRouter

router = APIRouter(tags=["Release Metadata"])


@router.get('/api/v1/release/status')
def release_status() -> dict[str, str | bool]:
    return {
        'release': '12.0',
        'status': 'installed',
        'production_ready': False,
        'validation': 'Use the local API-012.0 release gate before deployment.',
    }
