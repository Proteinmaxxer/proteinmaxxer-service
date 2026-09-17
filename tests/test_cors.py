from dataclasses import replace

from fastapi.testclient import TestClient

from main import create_app


def test_expo_web_preflight_and_error_responses(settings):
    with TestClient(create_app(replace(settings, cors_origins=("http://localhost:8081",)))) as client:
        response = client.options(
            "/auth/login",
            headers={
                "Origin": "http://localhost:8081",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,authorization",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:8081"
        response = client.post(
            "/auth/login",
            headers={"Origin": "http://localhost:8081"},
            json={"email": "person@example.com", "password": "wrong"},
        )
        assert response.status_code == 401
        assert response.headers["access-control-allow-origin"] == "http://localhost:8081"


def test_cors_rejects_unlisted_origins(settings):
    with TestClient(create_app(settings)) as client:
        response = client.options(
            "/auth/login",
            headers={"Origin": "https://untrusted.example", "Access-Control-Request-Method": "POST"},
        )
        assert response.status_code == 400
        assert "access-control-allow-origin" not in response.headers
