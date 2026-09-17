import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth.security import decode_access_token, unauthorized
from auth.service import AuthService

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthenticatedUser:
    id: str
    session_id: str


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


Auth = Annotated[AuthService, Depends(get_auth_service)]


def get_current_user(
    service: Auth,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> AuthenticatedUser:
    if credentials is None:
        raise unauthorized("Bearer access token required")
    claims = decode_access_token(service.settings, credentials.credentials)
    with service.database.connect() as conn:
        row = conn.execute(
            """SELECT s.id FROM sessions s JOIN users u ON s.user_id = u.id
            WHERE s.id = ? AND s.user_id = ? AND s.revoked_at IS NULL AND s.expires_at > ?""",
            (claims["sid"], claims["sub"], int(time.time())),
        ).fetchone()
        if row is None:
            raise unauthorized("Session expired or revoked")
    return AuthenticatedUser(id=claims["sub"], session_id=claims["sid"])


CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


def limit_auth_requests(request: Request, service: Auth):
    service.rate_limit(request.client.host if request.client else "unknown")
