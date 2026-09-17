# ProteinMaxxer service

FastAPI API with email/password, Google, and native Apple sign-in. All three methods
create a persistent account and profile, and return the same API token format.

## Run locally

Python 3.11 or later:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
# On a fresh checkout only; preserve existing values if .env already exists:
cp -n .env.example .env
.venv/bin/uvicorn main:app --reload
```

Interactive API documentation: [Swagger UI](http://localhost:8000/docs).
Health check: `GET /health`.

The local `.env` already has placeholder auth configuration. Existing environment
values are preserved. Email signup/login works locally with these placeholders.
Google and Apple return `503` until their client IDs are configured; fake provider
tokens are never accepted. Auth starts independently of `OPENAI_API_KEY`.

## Endpoints

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/signup` | Public | Email/password signup, profile creation, token pair |
| POST | `/auth/login` | Public | Email/password login |
| POST | `/auth/nonce` | Public | One-use Google/Apple login nonce, valid for 5 minutes |
| POST | `/auth/google` | Provider ID token + nonce in body | Google login or first-time signup |
| POST | `/auth/apple` | Provider ID token + nonce in body | Apple login or first-time signup |
| POST | `/auth/refresh` | Refresh token in body | Rotate access and refresh tokens |
| GET | `/auth/me` | Bearer access token | Current account, providers, and profile |
| POST | `/auth/logout` | Bearer access token | Immediately revoke the current session |
| POST | `/auth/logout-all` | Bearer access token | Immediately revoke all of this user's sessions |
| GET | `/profile` | Bearer access token | Current user's profile |
| PATCH | `/profile` | Bearer access token | Update supplied profile fields |
| POST | `/generate` | Bearer access token | Existing text generation API |
| POST | `/stream` | Bearer access token | Existing text streaming API |

Requests and responses use **snake_case**. The mobile client can map its camelCase
onboarding state to these fields when it is connected to this API.

## Email signup and login

```sh
curl -X POST http://localhost:8000/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "person@example.com",
    "password": "a-long-unique-password",
    "profile": {
      "display_name": "Alex",
      "weight_kg": 72,
      "height_cm": 175,
      "body_goal": "fitness",
      "diet_style": "vegetarian",
      "daily_protein_goal_g": 140,
      "budget_min_inr": 100,
      "budget_max_inr": 180,
      "cuisine_preferences": ["indian"]
    }
  }'
```

`profile` is optional; signup always creates a profile, even if empty. Passwords
must be 12–128 characters at signup and are stored as Argon2id hashes. Emails are
normalized to lowercase. Email/password signup leaves `email_verified: false`;
email delivery, email verification, password reset, and account linking are not
implemented in this increment. There is no email OTP or magic-link flow.

For login, send only `email` and `password` to `/auth/login`.

Successful signup, login, social login, and refresh return:

```json
{
  "access_token": "<signed ProteinMaxxer JWT>",
  "refresh_token": "<opaque random refresh token>",
  "token_type": "bearer",
  "expires_in": 900,
  "refresh_expires_in": 2592000,
  "is_new_user": true,
  "user": {
    "id": "<stable user UUID>",
    "email": "person@example.com",
    "email_verified": false,
    "providers": ["email"],
    "created_at": "<timestamp>",
    "profile": { "...": "profile fields and timestamps" }
  }
}
```

`is_new_user` is true only when the request creates an account. The token durations
above are defaults; `refresh_expires_in` decreases as a session ages.

## Google and Apple sign-in

1. Replace `GOOGLE_CLIENT_IDS` with a comma-separated list of accepted Google OAuth
   client IDs. Include the server/web audience and any iOS client ID used as the
   authorized presenter (`azp`). Replace `APPLE_CLIENT_IDS` with the iOS app's
   registered bundle ID. Configure the corresponding provider SDK in the mobile app.
2. Call `POST /auth/nonce` with `{"provider":"google"}` or `{"provider":"apple"}`.
3. Include the returned `nonce` in the provider authorization request. For native
   Apple sign-in, set the request's `nonce` to this exact value. The signed ID
   token's `nonce` claim must equal this value; a client wrapper that automatically
   hashes nonces needs an adapter to this contract. Do not send an unrelated
   locally generated nonce. Configure the Google client flow to request a nonce.
4. Obtain the Google ID token or Apple `identityToken` from the provider SDK. Send
   that token as `id_token` plus the original nonce to the matching API route:

```json
{
  "id_token": "<provider-issued ID token>",
  "nonce": "<nonce returned by this API>",
  "profile": {
    "display_name": "Alex",
    "daily_protein_goal_g": 140
  }
}
```

The server checks the signature using the provider's public keys, issuer, accepted
audience, expiry, subject, and nonce. Google's verification requirements are
documented in [Google's backend authentication guide](https://developers.google.com/identity/sign-in/web/backend-auth).
Apple's nonce and ID token verification requirements are documented in
[Verifying a user](https://developer.apple.com/documentation/signinwithapple/verifying-a-user).

Profiles are created only on first login. Google's verified token can supply the
initial display name and avatar. For Apple, send the separate first-consent name
in `profile.display_name`; later logins preserve it. This follows Apple's
[first-consent user information behavior](https://developer.apple.com/documentation/signinwithapple/authenticating-users-with-sign-in-with-apple).
Apple private relay email addresses are supported. An Apple identity without an
email is identified by its provider subject and has `email: null`.

Accounts are keyed by the verified provider subject. A matching email on an
unrelated identity returns `409`, rather than granting access to an existing
account. Use its original login method; explicit account linking is future work.

These native token-verification routes need client IDs and the providers' public
keys, which are fetched automatically. They do not require Google client secrets
or Apple private `.p8` keys. Authorization-code exchange, provider refresh tokens,
web redirect callbacks, and provider account-revocation notifications are outside
this API's current scope. The returned refresh token belongs to ProteinMaxxer.

## Use tokens for this and future APIs

```sh
curl http://localhost:8000/profile \
  -H 'Authorization: Bearer <access_token>'

curl -X PATCH http://localhost:8000/profile \
  -H 'Authorization: Bearer <access_token>' \
  -H 'Content-Type: application/json' \
  -d '{"daily_protein_goal_g": 150}'

curl -X POST http://localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

Send the **ProteinMaxxer access token** on subsequent API requests, not the Google
or Apple ID token. Access tokens last 15 minutes by default. Refresh tokens are
opaque random values stored only as SHA-256 hashes. Refresh rotates both tokens.
Atomically save the returned pair and serialize refresh attempts in the client:
reusing an old refresh token revokes its entire session and requires login again.
Sessions have an absolute 30-day lifetime by default, including after refresh.

`POST /auth/logout` takes no body and revokes the session identified by the Bearer
token, including access tokens already issued for it. `/auth/logout-all` revokes
all sessions for the current user. The client should clear its local credentials.
Use platform secure storage for mobile credentials.

Future FastAPI endpoints can use the shared dependency:

```python
from auth.dependencies import CurrentUser


@app.get("/my-items")
def my_items(user: CurrentUser):
    # Scope every database query to user.id.
    return {"user_id": user.id}
```

`CurrentUser` verifies the JWT and checks the persisted session's owner, expiry,
and revocation. It exposes `user.id` and `user.session_id`. Attach it to every
protected endpoint, or use `Depends(get_current_user)` on a router. JWT claims
contain user/session identifiers, issuer, audience, timestamps, token type, and
a unique token ID; no password or profile data is included.

Profiles support the mobile onboarding fields: display name/avatar, gender, age
range, measurements, workout frequency/intensity, body goal, diet, allergies and
notes, religious preferences/days, cuisines, protein goal, budget range, and
`skipped`. Read `/docs` for their allowed values. All measurements use kg/cm and
budgets use INR. Omitted PATCH fields stay unchanged; nullable fields can be
cleared with `null`. Protein goals are supplied by the client, not recalculated
by the authentication service. Email, account IDs, and providers cannot be edited
through the profile endpoint.

## Configuration and persistence

See `.env.example` for all settings. `JWT_SECRET_KEY` must be at least 32 bytes.
For deployment, set `APP_ENV=production` and generate a secret:

```sh
.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

The production environment rejects the documented placeholder secret. Replacing
the signing secret invalidates existing access tokens. Keep the real secret and
database private, use HTTPS, and retain the same secret across service restarts.

SQLite initializes automatically at `AUTH_DATABASE_PATH`, defaulting to
`data/proteinmaxxer.sqlite3`. Users, profiles, provider identities, sessions,
refresh-token hashes, and one-use nonces persist across restarts. This is a local
single-host database; multiple workers on the same host can share it. A deployment
on multiple hosts needs a shared database and corresponding migrations. The
service does not connect to the sibling Express service's database.

Auth routes share a per-client-IP limit of 30 requests per 60 seconds by default,
persisted in SQLite. If deploying behind a proxy, configure Uvicorn to trust
forwarded headers only from that proxy. Exceeded limits return `429` with a
`Retry-After` header. Auth/profile responses are marked `no-store`.

Errors use FastAPI's `detail` response: `401` invalid credentials/token/session,
`409` an account conflict, `422` invalid input, `429` rate limit, and `503` an
unconfigured or unavailable provider. Validation responses omit raw input values.

## Verify

```sh
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Tests use temporary SQLite databases and generated RSA signing keys. They run
real signature/claim verification with a local JWKS fixture, with no provider
credentials, OpenAI calls, or external network access. Live Google/Apple SDK login
still needs to be exercised after configuring real provider credentials.
