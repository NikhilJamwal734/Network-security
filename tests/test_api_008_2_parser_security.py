
"""
API-008.2
Cisco ASA Parser Security and Robustness Tests

Security requirements:
    - Uploaded configuration is untrusted data.
    - SQL-looking text must never execute.
    - Shell-looking text must never execute.
    - Python-looking text must never execute.
    - HTML-looking text must remain ordinary data.
    - Malformed configurations must not crash the API.
    - The parser must not call dangerous execution APIs.

These tests supplement, rather than replace, a security audit.
"""

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.serializers import serialize_firewall
from app.parsers.firewalls.cisco_asa import CiscoASAParser


client = TestClient(app)


# ============================================================
# TEST UTILITIES
# ============================================================

def upload_configuration(
    content: str,
):
    """
    Upload a configuration through the real FastAPI route.
    """

    return client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "security_test.conf",
                content.encode("utf-8"),
                "text/plain",
            )
        },
    )


def make_configuration(
    description: str,
) -> str:
    """
    Build a valid minimal ASA configuration.

    The description field contains the untrusted
    test string.
    """

    return (
        "hostname TEST-ASA\n"
        "interface GigabitEthernet0/0\n"
        f" description {description}\n"
        "!\n"
    )


# ============================================================
# SECURITY PAYLOADS
# ============================================================

SUSPICIOUS_TEXT = [
    "SELECT * FROM users; DROP TABLE users;",
    "' OR 1=1 --",
    "$(whoami)",
    "__import__('os').system('whoami')",
    "<img src=x onerror=alert(1)>",
    "../../private/configuration.txt",
]


# ============================================================
# TEST 1 — PARSER MUST PRESERVE INPUT AS DATA
# ============================================================

@pytest.mark.parametrize(
    "description",
    SUSPICIOUS_TEXT,
)
def test_parser_treats_suspicious_text_as_data(
    description,
):
    """
    The parser must preserve suspicious text
    as a configuration description.
    """

    parser = CiscoASAParser()

    firewall = parser.parse(
        make_configuration(description).splitlines()
    )

    configuration = serialize_firewall(firewall)

    assert firewall.hostname == "TEST-ASA"

    assert len(configuration["interfaces"]) == 1

    interface = configuration["interfaces"][0]

    assert interface["description"] == description


# ============================================================
# TEST 2 — API MUST HANDLE SUSPICIOUS CONTENT
# ============================================================

@pytest.mark.parametrize(
    "description",
    SUSPICIOUS_TEXT,
)
def test_api_treats_suspicious_text_as_data(
    description,
):
    """
    Upload the same payload through FastAPI.

    The request should succeed without executing
    or corrupting the description.
    """

    response = upload_configuration(
        make_configuration(description)
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["hostname"] == "TEST-ASA"

    assert "configuration" in data

    interfaces = data["configuration"]["interfaces"]

    assert len(interfaces) == 1

    assert interfaces[0]["description"] == description


# ============================================================
# TEST 3 — MALFORMED CONFIGURATION ROBUSTNESS
# ============================================================

MALFORMED_CONFIGURATIONS = [
    "route outside invalid invalid invalid\n",
    "access-list TEST extended permit tcp any any eq invalidport\n",
    "nat (inside,outside) static ???\n",
    "object network TEST\n subnet invalid invalid\n",
    "interface GigabitEthernet0/0\n ip address invalid invalid\n",
]


@pytest.mark.parametrize(
    "configuration",
    MALFORMED_CONFIGURATIONS,
)
def test_malformed_configuration_does_not_crash_api(
    configuration,
):
    """
    Malformed input may be rejected or produce
    a partial analysis, depending on parser support.

    It must not result in an unhandled server error.
    """

    response = upload_configuration(configuration)

    assert response.status_code in {
        200,
        400,
        413,
        422,
    }, (
        "Malformed input caused an unexpected "
        f"HTTP {response.status_code}: {response.text}"
    )


# ============================================================
# TEST 4 — UNKNOWN INPUT MUST NOT BE EXECUTED
# ============================================================

def test_unrecognized_text_is_rejected():
    """
    An upload containing no recognizable ASA syntax
    must not be treated as a valid configuration.
    """

    response = upload_configuration(
        "DROP TABLE users;\n"
        "SELECT * FROM passwords;\n"
    )

    assert response.status_code == 422


# ============================================================
# TEST 5 — ORIGINAL FIREWALL SYNTAX STILL WORKS
# ============================================================

def test_normal_firewall_configuration():
    """
    Security changes must not break normal parsing.
    """

    configuration = (
        "hostname TEST-ASA\n"
        "interface GigabitEthernet0/0\n"
        " nameif outside\n"
        " description WAN interface\n"
        "!\n"
    )

    response = upload_configuration(configuration)

    assert response.status_code == 200

    data = response.json()

    assert data["hostname"] == "TEST-ASA"
    assert data["vendor"] == "Cisco ASA"

    interfaces = data["configuration"]["interfaces"]

    assert len(interfaces) == 1
    assert interfaces[0]["name"] == "GigabitEthernet0/0"


# ============================================================
# TEST 6 — SOURCE CODE EXECUTION API AUDIT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

AUDITED_FILES = [
    "app/parsers/cisco_asa.py",
    "app/analyzer/engine.py",
    "app/reporting/report.py",
    "app/api/serializers.py",
]

FORBIDDEN_FUNCTIONS = {
    "eval",
    "exec",
    "compile",
    "__import__",
}

FORBIDDEN_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}


def get_call_name(node):
    """
    Convert a Python AST call target into a
    dotted name where possible.
    """

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)

        if parent:
            return f"{parent}.{node.attr}"

        return node.attr

    return None


@pytest.mark.parametrize(
    "relative_path",
    AUDITED_FILES,
)
def test_analysis_source_has_no_direct_execution_calls(
    relative_path,
):
    """
    Check for direct calls to dangerous functions.

    This is a basic static audit, not proof that
    every dynamic execution mechanism is absent.
    """

    source_path = PROJECT_ROOT / relative_path

    source = source_path.read_text(
        encoding="utf-8"
    )

    tree = ast.parse(
        source,
        filename=str(source_path),
    )

    violations = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = get_call_name(node.func)

        if (
            call_name in FORBIDDEN_FUNCTIONS
            or call_name in FORBIDDEN_CALLS
        ):
            violations.append(
                f"{call_name} at line {node.lineno}"
            )

    assert not violations, (
        f"Potentially dangerous execution call in "
        f"{relative_path}: {violations}"
    )


# ============================================================
# TEST 7 — CONFIGURATION REMAINS VALID JSON
# ============================================================

def test_suspicious_description_serializes_safely():
    """
    Dangerous-looking text should survive API
    JSON serialization without being executed.
    """

    description = (
        "__import__('os').system('whoami')"
    )

    response = upload_configuration(
        make_configuration(description)
    )

    assert response.status_code == 200

    data = response.json()

    serialized_description = (
        data["configuration"]["interfaces"][0]["description"]
    )

    assert serialized_description == description
