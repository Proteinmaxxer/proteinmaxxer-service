"""Environment configuration; provider placeholders never bypass verification."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent


def cors_origins_from_env() -> tuple[str, ...]:
    load_dotenv(ROOT / ".env")
    defaults = (
        "http://localhost:8081,http://127.0.0.1:8081"
        if os.getenv("APP_ENV", "development") == "development"
        else ""
    )
    return tuple(origin.strip() for origin in os.getenv("CORS_ORIGINS", defaults).split(",") if origin.strip())


def is_placeholder(value: str) -> bool:
    return not value or any(
        marker in value.lower()
        for marker in ("replace-me", "mock-", "your-", "change-me", "placeholder")
    )


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    database_path: str = str(ROOT / "data" / "proteinmaxxer.sqlite3")
    environment: str = "development"
    jwt_issuer: str = "proteinmaxxer-service"
    jwt_audience: str = "proteinmaxxer-api"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    google_client_ids: tuple[str, ...] = ()
    apple_client_ids: tuple[str, ...] = ()
    auth_rate_limit: int = 30
    auth_rate_window_seconds: int = 60
    cors_origins: tuple[str, ...] = ()

    def __post_init__(self):
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("APP_ENV must be development, test, or production")
        if len(self.jwt_secret.encode()) < 32:
            raise ValueError("JWT_SECRET_KEY must contain at least 32 bytes")
        if self.environment == "production" and is_placeholder(self.jwt_secret):
            raise ValueError("Replace the development JWT_SECRET_KEY before production")
        for value in (
            self.access_token_minutes,
            self.refresh_token_days,
            self.auth_rate_limit,
            self.auth_rate_window_seconds,
        ):
            if value <= 0:
                raise ValueError("Token lifetimes and rate limits must be positive")
        if self.database_path == ":memory:":
            raise ValueError("Use a SQLite file so connections share persistent state")

    @classmethod
    def from_env(cls):
        load_dotenv(ROOT / ".env")

        def client_ids(name):
            return tuple(v.strip() for v in os.getenv(name, "").split(",") if v.strip())

        return cls(
            jwt_secret=os.getenv("JWT_SECRET_KEY", ""),
            database_path=os.getenv(
                "AUTH_DATABASE_PATH", str(ROOT / "data" / "proteinmaxxer.sqlite3")
            ),
            environment=os.getenv("APP_ENV", "development"),
            jwt_issuer=os.getenv("JWT_ISSUER", "proteinmaxxer-service"),
            jwt_audience=os.getenv("JWT_AUDIENCE", "proteinmaxxer-api"),
            access_token_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")),
            refresh_token_days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30")),
            google_client_ids=client_ids("GOOGLE_CLIENT_IDS"),
            apple_client_ids=client_ids("APPLE_CLIENT_IDS"),
            auth_rate_limit=int(os.getenv("AUTH_RATE_LIMIT", "30")),
            auth_rate_window_seconds=int(os.getenv("AUTH_RATE_WINDOW_SECONDS", "60")),
            cors_origins=cors_origins_from_env(),
        )
