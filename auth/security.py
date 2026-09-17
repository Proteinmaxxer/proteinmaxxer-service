import hashlib
import time
import uuid

import jwt
from fastapi import HTTPException
from pwdlib import PasswordHash

from config import Settings

password_hasher = PasswordHash.recommended()
# Missing accounts still perform a password verification to reduce timing differences.
DUMMY_PASSWORD_HASH = password_hasher.hash("unused-dummy-password-verification")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def unauthorized(message="Invalid or expired credentials"):
    return HTTPException(401, message, headers={"WWW-Authenticate": "Bearer"})


def issue_access_token(settings: Settings, user_id: str, session_id: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": user_id,
            "sid": session_id,
            "jti": str(uuid.uuid4()),
            "type": "access",
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + settings.access_token_minutes * 60,
        },
        settings.jwt_secret,
        algorithm="HS256",
    )


def decode_access_token(settings: Settings, token: str) -> dict:
    if len(token) > 8192:
        raise unauthorized()
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "sid", "jti", "type", "iss", "aud", "iat", "exp"]},
        )
        if claims["type"] != "access" or not all(
            isinstance(claims[key], str) and claims[key] for key in ("sid", "sub", "jti")
        ):
            raise unauthorized()
        return claims
    except jwt.InvalidTokenError:
        raise unauthorized() from None
