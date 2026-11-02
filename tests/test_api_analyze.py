from fastapi.testclient import TestClient

from app.api.main import app


client = TestClient(app)


def upload_config(
    content: bytes,
    filename: str = "firewall.conf",
):
    return client.post(
        "/api/v1/analyze",
        files={
            "file": (
                filename,
                content,
                "application/octet-stream",
            )
        },
    )


def test_upload_valid_config():
    response = upload_config(
        b"hostname TEST-ASA\n"
        b"access-list OUTSIDE extended permit ip any any\n"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["vendor"] == "Cisco ASA"
    assert data["hostname"] == "TEST-ASA"
    assert data["summary"]["total_rules"] == 1
    assert data["summary"]["total_findings"] >= 1


def test_upload_returns_fw001():
    response = upload_config(
        b"hostname TEST-ASA\n"
        b"access-list OUTSIDE extended permit ip any any\n"
    )

    assert response.status_code == 200

    codes = {
        finding["code"]
        for finding in response.json()["findings"]
    }

    assert "FW-001" in codes


def test_upload_returns_security_score():
    response = upload_config(
        b"hostname TEST-ASA\n"
        b"access-list OUTSIDE extended permit ip any any\n"
    )

    assert response.status_code == 200

    summary = response.json()["summary"]

    assert 0 <= summary["security_score"] <= 100
    assert summary["risk_level"] == "CRITICAL"


def test_upload_returns_report_structure():
    response = upload_config(
        b"hostname TEST-ASA\n"
    )

    assert response.status_code == 200

    data = response.json()

    required_fields = {
        "vendor",
        "hostname",
        "summary",
        "findings",
        "warnings",
    }

    assert required_fields.issubset(data.keys())

    assert "configuration" in data
    assert isinstance(data["configuration"], dict)



def test_upload_rejects_empty_file():
    response = upload_config(b"")

    assert response.status_code == 400


def test_upload_rejects_whitespace_only():
    response = upload_config(b" \n\t ")

    assert response.status_code == 400


def test_upload_rejects_wrong_extension():
    response = upload_config(
        b"hostname TEST-ASA\n",
        filename="firewall.exe",
    )

    assert response.status_code == 400


def test_upload_accepts_cfg_extension():
    response = upload_config(
        b"hostname TEST-ASA\n",
        filename="firewall.cfg",
    )

    assert response.status_code == 200


def test_upload_accepts_txt_extension():
    response = upload_config(
        b"hostname TEST-ASA\n",
        filename="firewall.txt",
    )

    assert response.status_code == 200


def test_upload_rejects_oversized_file():
    response = upload_config(
        b"hostname TEST-ASA\n"
        + b"x" * (2 * 1024 * 1024),
    )

    assert response.status_code == 413


def test_upload_rejects_invalid_utf8():
    response = upload_config(
        b"hostname TEST-ASA\n\xff\xfe"
    )

    assert response.status_code == 400


def test_upload_rejects_binary_content():
    response = upload_config(
        b"hostname TEST-ASA\n\x00"
    )

    assert response.status_code == 400


def test_upload_rejects_unrecognized_configuration():
    response = upload_config(
        b"This is not a firewall configuration."
    )

    assert response.status_code == 422


def test_upload_requires_file():
    response = client.post("/api/v1/analyze")

    assert response.status_code == 422


def test_upload_returns_parser_warnings():
    response = upload_config(
        b"hostname TEST-ASA\n"
        b"object network BAD_HOST\n"
        b" host 999.999.999.999\n"
    )

    assert response.status_code == 200
    assert response.json()["warnings"]


def test_upload_detects_invalid_route_next_hop():
    response = upload_config(
        b"hostname TEST-ASA\n"
        b"route outside 10.10.0.0 255.255.0.0 "
        b"999.999.999.999 1\n"
    )

    assert response.status_code == 200

    codes = {
        finding["code"]
        for finding in response.json()["findings"]
    }

    assert "FW-025" in codes