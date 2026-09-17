"""Verify native Google/Apple ID tokens against fixed, trusted JWKS endpoints."""

import secrets
from dataclasses import dataclass

import jwt
from fastapi import HTTPException
from pydantic import EmailStr, HttpUrl, TypeAdapter, ValidationError

from auth.security import unauthorized
from config import Settings, is_placeholder


@dataclass(frozen=True)
class ProviderIdentity:
    subject: str
    email: str | None
    email_verified: bool
    display_name: str | None
    avatar_url: str | None


class ProviderVerifier:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.clients = {
            "google": jwt.PyJWKClient("https://www.googleapis.com/oauth2/v3/certs", timeout=5),
            "apple": jwt.PyJWKClient("https://appleid.apple.com/auth/keys", timeout=5),
        }

    def verify(self, provider: str, token: str, nonce: str) -> ProviderIdentity:
        audiences = (
            self.settings.google_client_ids
            if provider == "google"
            else self.settings.apple_client_ids
        )
        if not audiences or any(is_placeholder(value) for value in audiences):
            raise HTTPException(503, f"{provider.capitalize()} login is not configured")

        issuers = (
            ["https://accounts.google.com", "accounts.google.com"]
            if provider == "google"
            else ["https://appleid.apple.com"]
        )
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise unauthorized("Invalid provider token")
            key = self.clients[provider].get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=audiences,
                issuer=issuers,
                options={"require": ["sub", "iss", "aud", "iat", "exp", "nonce"]},
            )
        except jwt.PyJWKClientConnectionError:
            raise HTTPException(503, "Identity provider is temporarily unavailable") from None
        except jwt.PyJWTError:
            raise unauthorized("Invalid provider token") from None

        subject = claims.get("sub")
        token_nonce = claims.get("nonce")
        if (
            not isinstance(subject, str)
            or not subject
            or len(subject) > 255
            or not isinstance(token_nonce, str)
            or not secrets.compare_digest(token_nonce.encode(), nonce.encode())
        ):
            raise unauthorized("Invalid provider token")
        # OIDC requires checking the authorized presenter when one is supplied.
        if provider == "google" and claims.get("azp") is not None:
            if claims["azp"] not in audiences:
                raise unauthorized("Invalid provider token")
        if isinstance(claims["aud"], list) and len(claims["aud"]) > 1:
            if claims.get("azp") not in audiences:
                raise unauthorized("Invalid provider token")

        email = claims.get("email")
        if email is not None:
            try:
                email = str(TypeAdapter(EmailStr).validate_python(email)).lower()
            except ValidationError:
                raise unauthorized("Invalid provider email") from None
        verified = claims.get("email_verified") in (True, "true")
        if email and not verified:
            raise unauthorized("Provider email is not verified")
        if provider == "google" and not email:
            raise unauthorized("Google token must include a verified email")

        name = claims.get("name") if provider == "google" else None
        name = name.strip()[:100] if isinstance(name, str) and name.strip() else None
        picture = claims.get("picture") if provider == "google" else None
        try:
            picture = str(TypeAdapter(HttpUrl).validate_python(picture)) if picture else None
        except ValidationError:
            picture = None
        return ProviderIdentity(subject, email, bool(email and verified), name, picture)
