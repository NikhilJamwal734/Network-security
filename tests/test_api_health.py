"""
Tests for API-001: FastAPI application setup.
"""

from fastapi.testclient import TestClient

from app.api.main import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "Firewall Configuration Analyzer API"
    assert data["version"] == "1.0.0"
    assert data["status"] == "running"


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "firewall-analyzer-api"


def test_unknown_endpoint_returns_404():
    response = client.get("/does-not-exist")

    assert response.status_code == 404


def test_cors_allows_vite_frontend():
    response = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"]
        == "http://localhost:5173"
    )


def test_cors_rejects_unapproved_origin():
    response = client.options(
        "/health",
        headers={
            "Origin": "https://unapproved.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert (
        response.headers.get("access-control-allow-origin")
        != "https://unapproved.example"
    )