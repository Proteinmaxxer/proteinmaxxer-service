from fastapi import APIRouter, Depends, Response

from auth.dependencies import Auth, CurrentUser, limit_auth_requests
from auth.schemas import (
    AuthResponse,
    EmailCredentials,
    NonceRequest,
    NonceResponse,
    ProfileData,
    ProfileResponse,
    RefreshRequest,
    SignupRequest,
    SocialLoginRequest,
    UserResponse,
)

router = APIRouter(
    prefix="/auth", tags=["Authentication"], dependencies=[Depends(limit_auth_requests)]
)
profile_router = APIRouter(prefix="/profile", tags=["Profile"])


@router.post("/signup", response_model=AuthResponse, status_code=201)
def signup(body: SignupRequest, service: Auth):
    """Create an email/password account and profile, and start a session."""
    return service.signup(body)


@router.post("/login", response_model=AuthResponse)
def login(body: EmailCredentials, service: Auth):
    return service.login(body)


@router.post("/nonce", response_model=NonceResponse)
def nonce(body: NonceRequest, service: Auth):
    """Get a one-use nonce to include in the provider's sign-in request."""
    return service.create_nonce(body.provider)


@router.post("/google", response_model=AuthResponse)
def google_login(body: SocialLoginRequest, service: Auth):
    """Exchange a verified Google ID token for a ProteinMaxxer session."""
    return service.social_login("google", body)


@router.post("/apple", response_model=AuthResponse)
def apple_login(body: SocialLoginRequest, service: Auth):
    """Exchange a native Sign in with Apple identity token for a session."""
    return service.social_login("apple", body)


@router.post("/refresh", response_model=AuthResponse)
def refresh(body: RefreshRequest, service: Auth):
    """Rotate both tokens. A refresh token can only be used once."""
    return service.refresh(body.refresh_token)


@router.get("/me", response_model=UserResponse)
def me(user: CurrentUser, service: Auth):
    with service.database.connect() as conn:
        return service.public_user(conn, user.id)


@router.post("/logout", status_code=204)
def logout(user: CurrentUser, service: Auth):
    """Revoke the current session, including its access and refresh tokens."""
    service.logout(user.id, user.session_id)
    return Response(status_code=204)


@router.post("/logout-all", status_code=204)
def logout_all(user: CurrentUser, service: Auth):
    service.logout(user.id, user.session_id, all_sessions=True)
    return Response(status_code=204)


@profile_router.get("", response_model=ProfileResponse)
def get_profile(user: CurrentUser, service: Auth):
    with service.database.connect() as conn:
        return service.public_user(conn, user.id)["profile"]


@profile_router.patch("", response_model=ProfileResponse)
def patch_profile(body: ProfileData, user: CurrentUser, service: Auth):
    """Update only supplied fields in the signed-in user's profile."""
    return service.update_profile(user.id, body)
