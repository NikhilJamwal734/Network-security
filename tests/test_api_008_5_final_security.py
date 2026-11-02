
"""
API-008.5 — Final Security and Regression Tests

Firewall Configuration Analyzer

Security requirements:
    1. Uploaded files are always untrusted data.
    2. SQL-looking text must remain plain text.
    3. Shell-looking text must remain plain text.
    4. Python-looking text must remain plain text.
    5. HTML-looking text must remain plain text.
    6. Invalid uploads must fail safely.
    7. Oversized uploads must be rejected.
    8. Malformed configurations must not cause
       uncontrolled server errors.
    9. Valid firewall analysis must remain unchanged.
   10. Frontend source must avoid known unsafe HTML sinks.

These tests are regression and security checks.
Passing them does not prove the absence of every vulnerability.
"""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.security import untrusted_config


# ============================================================
# PATHS AND SETTINGS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

FRONTEND_SRC = PROJECT_ROOT / "frontend" / "src"

SAMPLE_CONFIG = (
    PROJECT_ROOT / "configs" / "firewall.conf"
)

MAX_UPLOAD_BYTES = untrusted_config.MAX_UPLOAD_BYTES

MAX_CONFIG_LINES = untrusted_config.MAX_CONFIG_LINES

MAX_LINE_LENGTH = untrusted_config.MAX_LINE_LENGTH


# ============================================================
# TEST CLIENT
# ============================================================

client = TestClient(app)


# ============================================================
# TEST HELPERS
# ============================================================

def upload_bytes(
    content: bytes,
    filename: str = "security_test.conf",
):
    """
    Submit raw bytes to the real analysis endpoint.
    """

    return client.post(
        "/api/v1/analyze",
        files={
            "file": (
                filename,
                content,
                "text/plain",
            )
        },
    )


def upload_text(
    content: str,
    filename: str = "security_test.conf",
):
    """
    Submit UTF-8 encoded text to the API.
    """

    return upload_bytes(
        content.encode("utf-8"),
        filename,
    )


def make_config(
    description: str,
):
    """
    Build a minimal supported Cisco ASA configuration.

    Description is intentionally untrusted.
    """

    return (
        "hostname SECURITY-TEST\n"
        "interface GigabitEthernet0/0\n"
        f" description {description}\n"
        "!\n"
    )


# ============================================================
# TEST 1 — MALICIOUS-LOOKING TEXT STAYS DATA
# ============================================================

SUSPICIOUS_DESCRIPTIONS = [
    "SELECT * FROM users; DROP TABLE users;",
    "' OR 1=1 --",
    "UNION SELECT username, password FROM users",
    "$(whoami)",
    "`whoami`",
    "__import__('os').system('whoami')",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "../../private/configuration.txt",
]


@pytest.mark.parametrize(
    "description",
    SUSPICIOUS_DESCRIPTIONS,
)
def test_suspicious_text_is_preserved_as_data(
    description,
):
    response = upload_text(
        make_config(description)
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["hostname"] == "SECURITY-TEST"

    interfaces = data["configuration"]["interfaces"]

    assert len(interfaces) == 1

    assert (
        interfaces[0]["description"]
        == description
    )


# ============================================================
# TEST 2 — INVALID FILE CONTENT
# ============================================================

INVALID_CONTENTS = [
    b"",
    b" \n\t ",
    b"\xff\xfe\xfa",
    b"hostname TEST-ASA\x00\n",
    b"hostname TEST-ASA\x01\n",
    b"hostname TEST-ASA\x7f\n",
]


@pytest.mark.parametrize(
    "content",
    INVALID_CONTENTS,
)
def test_invalid_upload_is_rejected(
    content,
):
    response = upload_bytes(content)

    assert response.status_code == 400

    # The error response must not expose a traceback.
    assert "Traceback (most recent call last)" not in (
        response.text
    )


# ============================================================
# TEST 3 — INVALID FILE EXTENSIONS
# ============================================================

@pytest.mark.parametrize(
    "filename",
    [
        "attack.exe",
        "attack.conf.exe",
        "configuration.json",
        "configuration",
    ],
)
def test_unsupported_extension_is_rejected(
    filename,
):
    response = upload_bytes(
        b"hostname TEST-ASA\n",
        filename=filename,
    )

    assert response.status_code == 400


# ============================================================
# TEST 4 — CASE-INSENSITIVE VALID EXTENSION
# ============================================================

def test_uppercase_conf_extension_is_accepted():
    response = upload_bytes(
        b"hostname TEST-ASA\n",
        filename="firewall.CONF",
    )

    assert response.status_code == 200

    assert response.json()["hostname"] == "TEST-ASA"


# ============================================================
# TEST 5 — MAXIMUM FILE SIZE
# ============================================================

def test_oversized_upload_is_rejected():
    oversized = (
        b"A" * (MAX_UPLOAD_BYTES + 1)
    )

    response = upload_bytes(oversized)

    assert response.status_code == 413


# ============================================================
# TEST 6 — MAXIMUM LINE LENGTH
# ============================================================

def test_excessively_long_line_is_rejected():
    config = (
        "hostname TEST-ASA\n"
        "interface GigabitEthernet0/0\n"
        " description "
        + ("A" * (MAX_LINE_LENGTH + 1))
        + "\n"
    )

    response = upload_text(config)

    assert response.status_code == 413


# ============================================================
# TEST 7 — MAXIMUM NUMBER OF LINES
# ============================================================

def test_excessive_line_count_is_rejected():
    config = (
        "hostname TEST-ASA\n"
        + ("!\n" * (MAX_CONFIG_LINES + 1))
    )

    response = upload_text(config)

    assert response.status_code == 413


# ============================================================
# TEST 8 — UNRECOGNIZED CONFIGURATION
# ============================================================

def test_unrecognized_content_is_rejected():
    response = upload_text(
        "SELECT * FROM users;\n"
        "DROP TABLE users;\n"
    )

    assert response.status_code == 422


# ============================================================
# TEST 9 — MISSING FILE
# ============================================================

def test_missing_file_is_rejected():
    response = client.post(
        "/api/v1/analyze"
    )

    assert response.status_code == 422


# ============================================================
# TEST 10 — MALFORMED ASA CONFIGURATIONS
# ============================================================

MALFORMED_CONFIGS = [
    "route outside invalid invalid invalid\n",
    (
        "access-list TEST extended permit "
        "tcp any any eq invalidport\n"
    ),
    "object network TEST\n subnet invalid invalid\n",
    (
        "interface GigabitEthernet0/0\n"
        " ip address invalid invalid\n"
    ),
]


@pytest.mark.parametrize(
    "configuration",
    MALFORMED_CONFIGS,
)
def test_malformed_asa_configuration_is_handled(
    configuration,
):
    response = upload_text(configuration)

    # Supported responses:
    # 200 = parser handled the partial configuration
    # 400 = invalid input
    # 413 = size/structure limit
    # 422 = unsupported or malformed configuration

    assert response.status_code in {
        200,
        400,
        413,
        422,
    }, (
        f"Unexpected response: "
        f"{response.status_code} "
        f"{response.text[:300]}"
    )


# ============================================================
# TEST 11 — JSON RESPONSE TYPE
# ============================================================

def test_api_returns_json_not_html():
    response = upload_text(
        make_config("<script>alert(1)</script>")
    )

    assert response.status_code == 200

    assert "application/json" in (
        response.headers.get(
            "content-type",
            ""
        )
    )

    data = response.json()

    assert data["configuration"]["interfaces"][0][
        "description"
    ] == "<script>alert(1)</script>"


# ============================================================
# TEST 12 — REPORT CONSISTENCY
# ============================================================

def test_repeated_analysis_is_consistent():
    configuration = (
        "hostname REPEAT-TEST\n"
        "access-list OUTSIDE extended "
        "permit ip any any\n"
    )

    first = upload_text(configuration)

    assert first.status_code == 200, first.text

    first_data = first.json()

    for _ in range(5):
        response = upload_text(configuration)

        assert response.status_code == 200

        data = response.json()

        assert data["hostname"] == first_data["hostname"]

        assert data["summary"] == first_data["summary"]

        assert (
            data["configuration"]
            == first_data["configuration"]
        )


# ============================================================
# TEST 13 — EXISTING FIREWALL REGRESSION
# ============================================================

def test_original_firewall_analysis_unchanged():
    """
    Check the known firewall.conf regression baseline.
    """

    assert SAMPLE_CONFIG.is_file(), (
        f"Missing sample configuration: {SAMPLE_CONFIG}"
    )

    content = SAMPLE_CONFIG.read_bytes()

    response = upload_bytes(
        content,
        filename="firewall.conf",
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["vendor"] == "Cisco ASA"

    assert data["hostname"] == "ASA-FIREWALL"

    summary = data["summary"]

    assert summary["security_score"] == 21

    assert summary["risk_level"] == "CRITICAL"

    assert summary["total_findings"] == 29

    configuration = data["configuration"]

    assert len(configuration["rules"]) == 9

    assert len(configuration["network_objects"]) == 7

    assert len(configuration["service_objects"]) == 2

    assert len(configuration["nat_rules"]) == 1

    assert len(configuration["routes"]) == 0

    assert len(configuration["interfaces"]) == 0


# ============================================================
# TEST 14 — FRONTEND RAW HTML SINK AUDIT
# ============================================================

UNSAFE_HTML_PATTERNS = [
    re.compile(r"\bdangerouslySetInnerHTML\b"),
    re.compile(r"\.innerHTML\s*="),
    re.compile(r"\bdocument\.write\s*\("),
]


def test_frontend_avoids_unsafe_html_sinks():
    """
    Search frontend TypeScript/TSX source for
    common unsafe raw HTML rendering operations.

    This is a lightweight source audit.
    It does not replace a browser security assessment.
    """

    assert FRONTEND_SRC.is_dir(), (
        "Frontend source directory not found."
    )

    violations = []

    source_files = [
        *FRONTEND_SRC.rglob("*.ts"),
        *FRONTEND_SRC.rglob("*.tsx"),
    ]

    for source_file in source_files:
        text = source_file.read_text(
            encoding="utf-8"
        )

        for pattern in UNSAFE_HTML_PATTERNS:
            for match in pattern.finditer(text):
                line_number = (
                    text.count(
                        "\n",
                        0,
                        match.start(),
                    ) + 1
                )

                violations.append(
                    f"{source_file.name}:"
                    f"{line_number}: "
                    f"{match.group(0)}"
                )

    assert not violations, (
        "Potentially unsafe HTML rendering "
        "operations found:\n"
        + "\n".join(violations)
    )
