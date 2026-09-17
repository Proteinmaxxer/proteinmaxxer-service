import json
import secrets
import time
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import ValidationError

from auth.providers import ProviderVerifier
from auth.schemas import ProfileData
from auth.security import (
    DUMMY_PASSWORD_HASH,
    digest,
    issue_access_token,
    password_hasher,
    unauthorized,
)
from config import Settings
from database import Database


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class AuthService:
    def __init__(self, settings: Settings, database: Database, verifier: ProviderVerifier):
        self.settings = settings
        self.database = database
        self.verifier = verifier

    def public_user(self, conn, user_id):
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise unauthorized()
        profile = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
        providers = ["email"] if row["password_hash"] else []
        providers.extend(
            r["provider"]
            for r in conn.execute(
                "SELECT provider FROM identities WHERE user_id = ? ORDER BY provider",
                (user_id,),
            )
        )
        return {
            "id": row["id"],
            "email": row["email"],
            "email_verified": bool(row["email_verified"]),
            "providers": providers,
            "created_at": row["created_at"],
            "profile": {
                **json.loads(profile["data"]),
                "user_id": user_id,
                "created_at": row["created_at"],
                "updated_at": profile["updated_at"],
            },
        }

    def create_user(self, conn, email, verified, password_hash, profile):
        user_id = str(uuid.uuid4())
        now = timestamp()
        conn.execute(
            "INSERT INTO users (id, email, email_verified, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, email, int(verified), password_hash, now),
        )
        conn.execute(
            "INSERT INTO profiles (user_id, data, updated_at) VALUES (?, ?, ?)",
            (user_id, profile.model_dump_json(), now),
        )
        return user_id

    def token_response(self, conn, user_id, session_id=None, is_new_user=False):
        now = int(time.time())
        if session_id is None:
            session_id = str(uuid.uuid4())
            expires_at = now + self.settings.refresh_token_days * 86400
            conn.execute(
                "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
                (session_id, user_id, expires_at),
            )
        else:
            expires_at = conn.execute(
                "SELECT expires_at FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()["expires_at"]
        refresh_token = secrets.token_urlsafe(48)
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, session_id) VALUES (?, ?)",
            (digest(refresh_token), session_id),
        )
        return {
            "access_token": issue_access_token(self.settings, user_id, session_id),
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": min(self.settings.access_token_minutes * 60, expires_at - now),
            "refresh_expires_in": expires_at - now,
            "is_new_user": is_new_user,
            "user": self.public_user(conn, user_id),
        }

    def signup(self, request):
        hashed = password_hasher.hash(request.password)
        with self.database.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM users WHERE email = ?", (request.email,)).fetchone():
                raise HTTPException(409, "An account with this email already exists")
            user_id = self.create_user(conn, request.email, False, hashed, request.profile)
            return self.token_response(conn, user_id, is_new_user=True)

    def login(self, request):
        with self.database.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (request.email,)).fetchone()
            stored_hash = (
                row["password_hash"] if row and row["password_hash"] else DUMMY_PASSWORD_HASH
            )
            valid, updated_hash = password_hasher.verify_and_update(request.password, stored_hash)
            if not valid or row is None or row["password_hash"] is None:
                raise unauthorized("Invalid email or password")
            if updated_hash:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?", (updated_hash, row["id"])
                )
            return self.token_response(conn, row["id"])

    def create_nonce(self, provider):
        nonce = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.database.connect() as conn:
            conn.execute("DELETE FROM oauth_nonces WHERE expires_at <= ?", (now,))
            conn.execute(
                "INSERT INTO oauth_nonces (nonce_hash, provider, expires_at) VALUES (?, ?, ?)",
                (digest(nonce), provider, now + 300),
            )
        return {"nonce": nonce, "expires_in": 300}

    def social_login(self, provider, request):
        with self.database.connect() as conn:
            nonce = conn.execute(
                "SELECT 1 FROM oauth_nonces WHERE nonce_hash = ? AND provider = ? AND expires_at > ?",
                (digest(request.nonce), provider, int(time.time())),
            ).fetchone()
        if nonce is None:
            raise unauthorized("Invalid, expired, or already used login nonce")
        # Perform remote verification before taking the database write lock.
        identity = self.verifier.verify(provider, request.id_token, request.nonce)
        with self.database.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            consumed = conn.execute(
                "DELETE FROM oauth_nonces WHERE nonce_hash = ? AND provider = ? AND expires_at > ?",
                (digest(request.nonce), provider, int(time.time())),
            )
            if consumed.rowcount != 1:
                raise unauthorized("Invalid, expired, or already used login nonce")
            row = conn.execute(
                "SELECT user_id FROM identities WHERE provider = ? AND subject = ?",
                (provider, identity.subject),
            ).fetchone()
            is_new = row is None
            if row:
                user_id = row["user_id"]
            else:
                # Never merge identities based only on matching email addresses.
                if (
                    identity.email
                    and conn.execute(
                        "SELECT 1 FROM users WHERE email = ?",
                        (identity.email,),
                    ).fetchone()
                ):
                    raise HTTPException(
                        409, "Email already registered; sign in using the original method"
                    )
                profile_data = request.profile.model_dump(mode="json")
                if not profile_data["display_name"]:
                    profile_data["display_name"] = identity.display_name
                if not profile_data["avatar_url"]:
                    profile_data["avatar_url"] = identity.avatar_url
                user_id = self.create_user(
                    conn,
                    identity.email,
                    identity.email_verified,
                    None,
                    ProfileData.model_validate(profile_data),
                )
                conn.execute(
                    "INSERT INTO identities (provider, subject, user_id) VALUES (?, ?, ?)",
                    (provider, identity.subject, user_id),
                )
            return self.token_response(conn, user_id, is_new_user=is_new)

    def refresh(self, refresh_token):
        now = int(time.time())
        reused = False
        with self.database.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT t.used_at, s.* FROM refresh_tokens t
                JOIN sessions s ON s.id = t.session_id WHERE t.token_hash = ?""",
                (digest(refresh_token),),
            ).fetchone()
            if not row or row["revoked_at"] is not None or row["expires_at"] <= now:
                raise unauthorized("Invalid or expired refresh token")
            if row["used_at"] is not None:
                conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (now, row["id"]))
                reused = True
            else:
                conn.execute(
                    "UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ?",
                    (now, digest(refresh_token)),
                )
                result = self.token_response(conn, row["user_id"], session_id=row["id"])
        # Raise after committing so revocation survives the error response.
        if reused:
            raise unauthorized("Refresh token reuse detected; sign in again")
        return result

    def logout(self, user_id, session_id, all_sessions=False):
        with self.database.connect() as conn:
            if all_sessions:
                conn.execute(
                    "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                    (int(time.time()), user_id),
                )
            else:
                conn.execute(
                    "UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ?",
                    (int(time.time()), session_id, user_id),
                )

    def update_profile(self, user_id, request):
        with self.database.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT data FROM profiles WHERE user_id = ?", (user_id,)).fetchone()
            data = json.loads(row["data"])
            data.update(request.model_dump(mode="json", exclude_unset=True))
            try:
                profile = ProfileData.model_validate(data)
            except ValidationError:
                raise HTTPException(
                    422, "Profile update contains an invalid budget range"
                ) from None
            conn.execute(
                "UPDATE profiles SET data = ?, updated_at = ? WHERE user_id = ?",
                (profile.model_dump_json(), timestamp(), user_id),
            )
            return self.public_user(conn, user_id)["profile"]

    def rate_limit(self, client_ip):
        now = int(time.time())
        window = self.settings.auth_rate_window_seconds
        bucket = digest(f"{client_ip}:{now // window}")
        with self.database.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM rate_limits WHERE expires_at <= ?", (now,))
            row = conn.execute(
                "SELECT attempts FROM rate_limits WHERE bucket = ?", (bucket,)
            ).fetchone()
            if row and row["attempts"] >= self.settings.auth_rate_limit:
                raise HTTPException(
                    429,
                    "Too many authentication requests",
                    headers={"Retry-After": str(window - now % window)},
                )
            conn.execute(
                """INSERT INTO rate_limits (bucket, attempts, expires_at) VALUES (?, 1, ?)
                ON CONFLICT(bucket) DO UPDATE SET attempts = attempts + 1""",
                (bucket, (now // window + 1) * window),
            )
