import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from auth.security import digest, password_hasher
from config import Settings
from main import create_app

PASSWORD = "a-long-test-password-123"


def signup(client, email="person@example.com", profile=None):
    response = client.post(
        "/auth/signup",
        json={
            "email": email,
            "password": PASSWORD,
            "profile": profile or {},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def headers(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def social(client, sign, provider, profile=None, **claims):
    nonce = client.post("/auth/nonce", json={"provider": provider}).json()["nonce"]
    body = {
        "id_token": sign(provider, nonce, **claims),
        "nonce": nonce,
        "profile": profile or {},
    }
    return client.post(f"/auth/{provider}", json=body), body


def test_signup_login_profile_and_hashed_storage(app, settings):
    first = signup(
        app,
        "PERSON@example.com",
        {
            "display_name": "Ada",
            "weight_kg": 70,
            "daily_protein_goal_g": 140,
            "diet_style": "vegetarian",
            "cuisine_preferences": ["indian"],
        },
    )
    assert first["is_new_user"] is True
    assert first["user"]["email"] == "person@example.com"
    assert first["user"]["email_verified"] is False
    assert first["user"]["providers"] == ["email"]
    assert first["expires_in"] == 900
    assert first["refresh_expires_in"] == 30 * 86400
    claims = jwt.decode(
        first["access_token"],
        settings.jwt_secret,
        algorithms=["HS256"],
        audience=settings.jwt_audience,
    )
    assert claims["sub"] == first["user"]["id"]
    assert claims["type"] == "access"
    with app.app.state.auth_service.database.connect() as conn:
        user = conn.execute("SELECT * FROM users").fetchone()
        token = conn.execute("SELECT token_hash FROM refresh_tokens").fetchone()
        assert user["password_hash"].startswith("$argon2id$")
        assert password_hasher.verify(PASSWORD, user["password_hash"])
        assert token["token_hash"] == digest(first["refresh_token"])
        assert token["token_hash"] != first["refresh_token"]
    assert PASSWORD not in str(first)
    assert "password_hash" not in str(first)
    assert app.get("/auth/me", headers=headers(first)).json() == first["user"]
    response = app.post("/auth/login", json={"email": "PERSON@example.com", "password": PASSWORD})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["user"]["id"] == first["user"]["id"]
    assert response.json()["is_new_user"] is False
    assert response.json()["access_token"] != first["access_token"]


def test_duplicate_and_generic_invalid_login(app):
    signup(app)
    assert (
        app.post(
            "/auth/signup", json={"email": "PERSON@example.com", "password": PASSWORD}
        ).status_code
        == 409
    )
    known = app.post("/auth/login", json={"email": "person@example.com", "password": "wrong"})
    unknown = app.post("/auth/login", json={"email": "missing@example.com", "password": "wrong"})
    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "invalid", "password": PASSWORD},
        {"email": "person@example.com", "password": "tiny-secret"},
        {"email": "person@example.com", "password": "x" * 129},
        {"email": "person@example.com", "password": PASSWORD, "user_id": "injected"},
        {"email": "person@example.com", "password": PASSWORD, "profile": {"weight_kg": -1}},
        {
            "email": "person@example.com",
            "password": PASSWORD,
            "profile": {"budget_min_inr": 200, "budget_max_inr": 100},
        },
    ],
)
def test_invalid_signup_rejects_without_echoing_password(app, payload):
    response = app.post("/auth/signup", json=payload)
    assert response.status_code == 422
    assert payload["password"] not in response.text
    with app.app.state.auth_service.database.connect() as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0


def test_profiles_are_isolated_and_patch_preserves_other_fields(app):
    first = signup(
        app,
        profile={
            "display_name": "First",
            "weight_kg": 70,
            "budget_min_inr": 100,
            "budget_max_inr": 200,
        },
    )
    second = signup(app, "second@example.com", {"display_name": "Second"})
    patched = app.patch("/profile", headers=headers(first), json={"display_name": "Updated"})
    assert patched.status_code == 200
    assert patched.json()["weight_kg"] == 70
    assert app.get("/profile", headers=headers(second)).json()["display_name"] == "Second"
    assert (
        app.patch(
            "/profile", headers=headers(first), json={"user_id": second["user"]["id"]}
        ).status_code
        == 422
    )
    assert (
        app.patch("/profile", headers=headers(first), json={"budget_min_inr": 250}).status_code
        == 422
    )
    assert app.get("/profile", headers=headers(first)).json()["budget_min_inr"] == 100
    assert (
        app.patch("/profile", headers=headers(first), json={"weight_kg": None}).json()["weight_kg"]
        is None
    )


@pytest.mark.parametrize(
    "path,method",
    [("/profile", "get"), ("/auth/me", "get"), ("/generate", "post"), ("/stream", "post")],
)
def test_missing_auth_is_rejected(app, path, method):
    kwargs = {"json": {"prompt": "hello"}} if method == "post" else {}
    response = getattr(app, method)(path, **kwargs)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "change",
    ["expired", "audience", "issuer", "signature", "type", "missing_sid", "bad_sid", "subject"],
)
def test_invalid_access_tokens(app, settings, change):
    tokens = signup(app)
    claims = jwt.decode(
        tokens["access_token"],
        settings.jwt_secret,
        algorithms=["HS256"],
        audience=settings.jwt_audience,
    )
    key = settings.jwt_secret
    if change == "expired":
        claims["iat"], claims["exp"] = int(time.time()) - 200, int(time.time()) - 100
    elif change == "audience":
        claims["aud"] = "another-api"
    elif change == "issuer":
        claims["iss"] = "another-service"
    elif change == "signature":
        key = "different-secret-" + "x" * 40
    elif change == "type":
        claims["type"] = "refresh"
    elif change == "missing_sid":
        del claims["sid"]
    elif change == "bad_sid":
        claims["sid"] = {"invalid": "type"}
    else:
        claims["sub"] = "another-user"
    token = jwt.encode(claims, key, algorithm="HS256")
    assert app.get("/profile", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_refresh_rotation_and_reuse_revoke_entire_session(app):
    first = signup(app)
    rotated = app.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert rotated.status_code == 200
    second = rotated.json()
    assert first["refresh_token"] != second["refresh_token"]
    assert first["access_token"] != second["access_token"]
    assert app.get("/profile", headers=headers(second)).status_code == 200
    assert (
        app.get(
            "/profile", headers={"Authorization": f"Bearer {second['refresh_token']}"}
        ).status_code
        == 401
    )
    assert app.post("/auth/refresh", json={"refresh_token": "z" * 64}).status_code == 401
    assert (
        app.post("/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    )
    assert (
        app.post("/auth/refresh", json={"refresh_token": second["refresh_token"]}).status_code
        == 401
    )
    assert app.get("/profile", headers=headers(second)).status_code == 401
    assert app.get("/profile", headers=headers(first)).status_code == 401


def test_logout_current_and_all_sessions(app):
    first = signup(app)
    second = app.post(
        "/auth/login", json={"email": "person@example.com", "password": PASSWORD}
    ).json()
    other = signup(app, "other@example.com")
    assert app.post("/auth/logout", headers=headers(first)).status_code == 204
    assert app.get("/profile", headers=headers(first)).status_code == 401
    assert (
        app.post("/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    )
    assert app.get("/profile", headers=headers(second)).status_code == 200
    third = app.post(
        "/auth/login", json={"email": "person@example.com", "password": PASSWORD}
    ).json()
    assert app.post("/auth/logout-all", headers=headers(second)).status_code == 204
    assert app.get("/profile", headers=headers(second)).status_code == 401
    assert app.get("/profile", headers=headers(third)).status_code == 401
    assert app.get("/profile", headers=headers(other)).status_code == 200


def test_session_expiry(app):
    tokens = signup(app)
    with app.app.state.auth_service.database.connect() as conn:
        conn.execute("UPDATE sessions SET expires_at = ?", (int(time.time()) - 1,))
    assert app.get("/profile", headers=headers(tokens)).status_code == 401
    assert (
        app.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 401
    )


def test_accounts_profiles_and_sessions_survive_restart(settings):
    with TestClient(create_app(settings)) as first_app:
        tokens = signup(first_app, profile={"display_name": "Persistent"})
    with TestClient(create_app(settings)) as second_app:
        response = second_app.get("/profile", headers=headers(tokens))
        assert response.status_code == 200
        assert response.json()["display_name"] == "Persistent"
        assert (
            second_app.post(
                "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            ).status_code
            == 200
        )


@pytest.mark.parametrize("provider", ["google", "apple"])
def test_provider_signup_and_repeat_login_preserve_profile(app, provider_token, provider):
    response, _ = social(
        app, provider_token, provider, {"display_name": "First Name", "weight_kg": 72}
    )
    assert response.status_code == 200, response.text
    tokens = response.json()
    assert tokens["is_new_user"] is True
    assert tokens["user"]["email_verified"] is True
    assert tokens["user"]["providers"] == [provider]
    assert app.get("/profile", headers=headers(tokens)).status_code == 200
    # Repeat Apple consent may omit email/name. Stable provider subject remains the identity.
    claims = {"email": None} if provider == "apple" else {}
    repeat, _ = social(
        app, provider_token, provider, {"display_name": "Overwrite Attempt"}, **claims
    )
    assert repeat.status_code == 200
    assert repeat.json()["is_new_user"] is False
    assert repeat.json()["user"] == tokens["user"]
    with app.app.state.auth_service.database.connect() as conn:
        assert conn.execute("SELECT count(*) FROM profiles").fetchone()[0] == 1


def test_google_profile_defaults_and_apple_private_relay(app, provider_token):
    google, _ = social(app, provider_token, "google")
    assert google.json()["user"]["profile"]["display_name"] == "Google User"
    assert google.json()["user"]["profile"]["avatar_url"] == "https://example.com/avatar.png"
    apple, _ = social(app, provider_token, "apple", email="private@privaterelay.appleid.com")
    assert apple.status_code == 200
    assert apple.json()["user"]["email"] == "private@privaterelay.appleid.com"


@pytest.mark.parametrize("provider", ["google", "apple"])
def test_matching_email_does_not_link_or_take_over_existing_account(app, provider_token, provider):
    existing = signup(app)
    response, _ = social(app, provider_token, provider, email="person@example.com")
    assert response.status_code == 409
    assert app.get("/auth/me", headers=headers(existing)).json()["providers"] == ["email"]


@pytest.mark.parametrize("provider", ["google", "apple"])
@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "another-app"},
        {"iss": "https://attacker.example.com"},
        {"exp": 1},
        {"iat": 9999999999},
        {"sub": None},
        {"nonce": None},
        {"email_verified": False},
        {"email_verified": "false"},
        {"email": "invalid"},
    ],
)
def test_provider_invalid_claims_rejected(app, provider_token, provider, claims):
    response, _ = social(app, provider_token, provider, **claims)
    assert response.status_code == 401, response.text
    with app.app.state.auth_service.database.connect() as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0


@pytest.mark.parametrize("provider", ["google", "apple"])
def test_nonce_replay_expiry_mismatch_and_cross_provider(app, provider_token, provider):
    response, body = social(app, provider_token, provider)
    assert response.status_code == 200
    assert app.post(f"/auth/{provider}", json=body).status_code == 401
    other_nonce = app.post("/auth/nonce", json={"provider": provider}).json()["nonce"]
    body["nonce"] = other_nonce
    assert app.post(f"/auth/{provider}", json=body).status_code == 401
    other_provider = "apple" if provider == "google" else "google"
    body["id_token"] = provider_token(other_provider, other_nonce)
    assert app.post(f"/auth/{other_provider}", json=body).status_code == 401
    body["id_token"] = provider_token(provider, other_nonce)
    with app.app.state.auth_service.database.connect() as conn:
        conn.execute("UPDATE oauth_nonces SET expires_at = ?", (int(time.time()) - 1,))
    assert app.post(f"/auth/{provider}", json=body).status_code == 401


@pytest.mark.parametrize("kind", ["bad_signature", "unsigned", "hs256", "malformed", "unknown_key"])
def test_provider_signature_verification(app, provider_token, kind):
    nonce = app.post("/auth/nonce", json={"provider": "google"}).json()["nonce"]
    token = provider_token("google", nonce)
    claims = jwt.decode(token, options={"verify_signature": False})
    if kind == "bad_signature":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})
    elif kind == "unsigned":
        token = jwt.encode(claims, "", algorithm="none")
    elif kind == "hs256":
        token = jwt.encode(claims, "x" * 40, algorithm="HS256", headers={"kid": "test-key"})
    elif kind == "unknown_key":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "unknown-key"})
    else:
        token = "malformed.token"
    assert app.post("/auth/google", json={"id_token": token, "nonce": nonce}).status_code == 401


def test_google_authorized_presenter(app, provider_token, settings):
    invalid, _ = social(app, provider_token, "google", azp="another-client")
    assert invalid.status_code == 401
    valid, _ = social(app, provider_token, "google", azp=settings.google_client_ids[1])
    assert valid.status_code == 200


def test_provider_outage_is_503(app, provider_token, monkeypatch):
    def unavailable(*args):
        raise jwt.PyJWKClientConnectionError("upstream unavailable")

    monkeypatch.setattr(
        app.app.state.auth_service.verifier.clients["google"],
        "get_signing_key_from_jwt",
        unavailable,
    )
    response, _ = social(app, provider_token, "google")
    assert response.status_code == 503
    assert "upstream unavailable" not in response.text


@pytest.mark.parametrize("provider", ["google", "apple"])
def test_placeholder_provider_configuration_is_disabled(settings, provider):
    configured = replace(
        settings, google_client_ids=("mock-google-id",), apple_client_ids=("mock-apple-id",)
    )
    with TestClient(create_app(configured)) as client:
        nonce = client.post("/auth/nonce", json={"provider": provider}).json()["nonce"]
        response = client.post(f"/auth/{provider}", json={"id_token": "fake-token", "nonce": nonce})
        assert response.status_code == 503


def test_rate_limit_shared_and_health_unaffected(settings):
    configured = replace(settings, auth_rate_limit=2)
    with TestClient(create_app(configured)) as client:
        for _ in range(2):
            assert client.post("/auth/nonce", json={"provider": "google"}).status_code == 200
        response = client.post(
            "/auth/login", json={"email": "person@example.com", "password": PASSWORD}
        )
        assert response.status_code == 429
        assert 0 < int(response.headers["retry-after"]) <= 60
        assert client.get("/health").status_code == 200
    with TestClient(create_app(configured)) as restarted:
        assert restarted.post("/auth/nonce", json={"provider": "apple"}).status_code == 429


def test_concurrent_signup_has_only_one_account_and_profile(app):
    def attempt(_):
        return app.post("/auth/signup", json={"email": "person@example.com", "password": PASSWORD})

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(attempt, range(2)))
    assert sorted(response.status_code for response in responses) == [201, 409]
    with app.app.state.auth_service.database.connect() as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM profiles").fetchone()[0] == 1


def test_concurrent_refresh_only_rotates_once(app):
    tokens = signup(app)

    def attempt(_):
        return app.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(attempt, range(2)))
    assert sorted(response.status_code for response in responses) == [200, 401]
    winner = next(response.json() for response in responses if response.status_code == 200)
    assert app.get("/profile", headers=headers(winner)).status_code == 401


def test_configuration_rejects_missing_short_and_production_placeholder_secrets():
    for secret in ("", "short"):
        with pytest.raises(ValueError, match="32 bytes"):
            Settings(jwt_secret=secret)
    with pytest.raises(ValueError, match="before production"):
        Settings(jwt_secret="mock-development-secret-" + "x" * 40, environment="production")


def test_generation_routes_use_same_auth_dependency(app, monkeypatch):
    tokens = signup(app)
    client = MagicMock()
    client.__enter__.return_value = client
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="generated"))]
    )
    monkeypatch.setattr("main.get_openai_client", lambda: client)
    response = app.post("/generate", headers=headers(tokens), json={"prompt": "hello"})
    assert response.status_code == 200
    assert response.json() == {"output": "generated"}
    stream = MagicMock()
    stream.__enter__.return_value = [
        SimpleNamespace(choices=[]),
        SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=None))]),
        SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="hello"))]),
    ]
    client.chat.completions.create.return_value = stream
    response = app.post("/stream", headers=headers(tokens), json={"prompt": "hello"})
    assert response.status_code == 200
    assert response.text == "hello"


def test_auth_works_without_openai_key(app, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    tokens = signup(app)
    assert app.get("/profile", headers=headers(tokens)).status_code == 200
    assert (
        app.post("/generate", headers=headers(tokens), json={"prompt": "hello"}).status_code == 503
    )
