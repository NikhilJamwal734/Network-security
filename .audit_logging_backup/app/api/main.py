"""FastAPI backend for Universal Network Security Configuration Analyzer.

SECURITY: All uploaded configurations are untrusted data; never execute or
apply lines as SQL, shell, Python, or device commands.

API-009.3 adds an opt-in normalized endpoint while preserving the existing
Cisco ASA endpoint, root response, and API-009.2 universal endpoint.
"""

import logging

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.analyzer.engine import FirewallAnalyzer
from app.parsers.cisco_asa import CiscoASAParser
from app.reporting.report import generate_report
from app.api.serializers import serialize_firewall
from app.api.universal import router as universal_router
from app.api.normalized import router as normalized_router
from app.api.assessment import router as assessment_router
from app.api.validated import router as validated_router
from app.api.deep_review import router as deep_review_router
from app.api.precision_review import router as precision_review_router
from app.api.rule_correlation import router as rule_correlation_router
from app.api.correlation_assurance import router as correlation_assurance_router
from app.api.object_resolution import router as object_resolution_router
from app.api.object_assurance import router as object_assurance_router
from app.api.service_ipv6 import router as service_ipv6_router
from app.api.nat_route_reachability import router as nat_route_router
from app.api.ids_configuration import router as ids_configuration_router
from app.api.consolidation import router as consolidation_router
from app.api.correlation_accuracy import router as correlation_accuracy_router
from app.api.report_validation import router as report_validation_router
from app.api.pdf_export_readiness import router as pdf_export_readiness_router
from app.api.pipeline_validation import router as pipeline_validation_router
from app.api.hardened_analysis import router as hardened_analysis_router
from app.api.release_status import router as release_status_router
from app.api.ids_bundle import router as ids_bundle_router
from app.security.untrusted_config import read_untrusted_config

logger = logging.getLogger(__name__)

API_VERSION = "1.2.0"
LEGACY_ROOT_VERSION = "1.0.0"

app = FastAPI(
    title="Universal Network Security Configuration Analyzer API",
    description=(
        "API for securely parsing and analyzing network security "
        "configurations, including firewall, IDS, and IPS platforms "
        "as supported adapters become available."
    ),
    version=API_VERSION,
)

# Both routers define their own full /api/v1/... route paths.
# Do not add another /api/v1 prefix at registration.
app.include_router(universal_router)
app.include_router(normalized_router)
app.include_router(assessment_router)
app.include_router(validated_router)
app.include_router(deep_review_router)
app.include_router(precision_review_router)
app.include_router(rule_correlation_router)
app.include_router(correlation_assurance_router)
app.include_router(object_resolution_router)
app.include_router(object_assurance_router)
app.include_router(service_ipv6_router)
app.include_router(nat_route_router)
app.include_router(ids_configuration_router)
app.include_router(consolidation_router)
app.include_router(correlation_accuracy_router)
app.include_router(report_validation_router)
app.include_router(pdf_export_readiness_router)
app.include_router(pipeline_validation_router)
app.include_router(hardened_analysis_router)
app.include_router(release_status_router)
app.include_router(ids_bundle_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)


@app.get("/", tags=["System"])
def root():
    """Preserve the existing root response required by API health tests."""
    return {
        "name": "Firewall Configuration Analyzer API",
        "version": LEGACY_ROOT_VERSION,
        "status": "running",
    }


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "firewall-analyzer-api",
    }


SUPPORTED_PREFIXES = (
    "hostname ",
    "interface ",
    "object network ",
    "object-group network ",
    "object service ",
    "object-group service ",
    "access-list ",
    "route ",
    "nat ",
)


def contains_supported_configuration(lines: list[str]) -> bool:
    """Text matching only; never execute uploaded configuration lines."""
    return any(
        line.strip().lower().startswith(SUPPORTED_PREFIXES)
        for line in lines
    )


@app.post("/api/v1/analyze", tags=["Analysis"])
async def analyze_configuration(file: UploadFile = File(...)):
    """Legacy Cisco ASA endpoint. Output and validation remain unchanged."""
    try:
        configuration_text = await read_untrusted_config(file)
    finally:
        await file.close()

    lines = configuration_text.splitlines()
    if not contains_supported_configuration(lines):
        raise HTTPException(
            status_code=422,
            detail="No supported Cisco ASA configuration commands found.",
        )

    try:
        firewall = CiscoASAParser().parse(lines)
    except (ValueError, TypeError, OverflowError):
        logger.warning("Rejected malformed Cisco ASA configuration")
        raise HTTPException(
            status_code=422,
            detail=(
                "Unable to parse the firewall configuration. "
                "Check the configuration syntax."
            ),
        ) from None

    findings = FirewallAnalyzer(firewall).analyze()
    report = generate_report(firewall=firewall, findings=findings)
    response = report.to_dict()
    response["configuration"] = serialize_firewall(firewall)
    return response
