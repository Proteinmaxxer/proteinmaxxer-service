import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from config import Settings
from main import create_app


@pytest.fixture
def settings(tmp_path):
    return Settings(
        jwt_secret="test-suite-secret-only-" + "x" * 40,
        database_path=str(tmp_path / "auth.sqlite3"),
        environment="test",
        google_client_ids=(
            "google-web.apps.googleusercontent.com",
            "google-ios.apps.googleusercontent.com",
        ),
        apple_client_ids=("com.proteinmaxxer.ios",),
        auth_rate_limit=1000,
    )


@pytest.fixture(scope="session")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def app(settings, signing_key, monkeypatch):
    app = create_app(settings)
    with TestClient(app) as client:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
        jwk.update(kid="test-key", use="sig", alg="RS256")
        for jwks in app.state.auth_service.verifier.clients.values():
            monkeypatch.setattr(jwks, "fetch_data", lambda: {"keys": [jwk]})
        yield client


@pytest.fixture
def provider_token(settings, signing_key):
    def sign(provider, requested_nonce, **overrides):
        now = int(time.time())
        claims = {
            "iss": "https://accounts.google.com"
            if provider == "google"
            else "https://appleid.apple.com",
            "aud": settings.google_client_ids[0]
            if provider == "google"
            else settings.apple_client_ids[0],
            "sub": f"{provider}-subject-123",
            "email": f"{provider}@example.com",
            "email_verified": True if provider == "google" else "true",
            "iat": now,
            "exp": now + 300,
            "nonce": requested_nonce,
        }
        if provider == "google":
            claims.update(name="Google User", picture="https://example.com/avatar.png")
        claims.update(overrides)
        claims = {key: value for key, value in claims.items() if value is not None}
        return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"})

    return sign
