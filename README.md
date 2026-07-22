# auth2

Auth0-compatible authentication platform. Self-host on GCP or AWS at **half the cost**. Same OAuth, OIDC & Management API — [switch from Auth0](website/migration.html) in hours.

Stores users in SQLite or PostgreSQL, issues RS256 JWTs.

## Endpoints

### OAuth/OIDC
- `GET /authorize` — authorization code, implicit (`response_type=token` / `id_token`), PKCE (`code_challenge`), `audience`
- `GET /login` — login page (customizable via `LOGIN_PAGE_TEMPLATE`)
- `POST /login` — submit credentials for auth code or implicit flow
- `GET /callback/social` — OAuth callback for Google, GitHub (`connection=google|github` on `/authorize`)
- `POST /oauth/token` — token endpoint
  - `grant_type=password` / `password-realm` — resource owner password
  - `grant_type=client_credentials` — client credentials
  - `grant_type=authorization_code` — exchange code for tokens (PKCE with `code_verifier`)
  - `grant_type=refresh_token` — refresh with token rotation
  - `grant_type=urn:ietf:params:oauth:grant-type:device_code` — device code flow
  - `grant_type=urn:openid:params:grant-type:ciba` — CIBA (Client Initiated Backchannel Authentication)
- `POST /oauth/revoke` — revoke refresh or access token
- `POST /oauth/introspect` — RFC 7662 token introspection
- `POST /oauth/device/code` — request device code (client_id, scope, audience)
- `GET /oauth/device/authorize` — user enters code and authenticates
- `POST /oauth/ciba/request` — CIBA: request auth (login_hint, scope, client_id); returns auth_req_id, interval, expires_in
- `GET /ciba/verify?auth_req_id=` — CIBA: page where user approves or denies
- `GET /userinfo` — OIDC userinfo (Bearer token)
- `POST /tokeninfo` — Auth0 legacy token introspection
- `GET /.well-known/jwks.json` — JWKS
- `GET /.well-known/openid-configuration` — OIDC discovery (includes `revocation_endpoint`, `introspection_endpoint`)
- `GET /v2/logout` — logout (redirect to `returnTo` or `post_logout_redirect_uri`)

### Passkeys (WebAuthn)
- `POST /webauthn/register/begin` — start passkey registration (requires session)
- `POST /webauthn/register/finish?sessionId=` — complete registration
- `POST /webauthn/assertion/begin` — start passkey login (body: `{"email": "user@example.com"}`)
- `POST /webauthn/assertion/finish?sessionId=` — complete passkey login

Use `/authorize` with `prompt=passkey` or `connection=webauthn` to redirect to passkey flow.

### Passwordless & MFA
- `POST /passwordless/start` — magic link or SMS OTP (`auth_type=magiclink|sms`)
- `GET /passwordless/verify` — verify token, redirect with code or tokens
- `POST /passwordless/confirm` — password reset confirmation
- `POST /passwordless/reset` — request password reset
- `POST /mfa/enroll` — start MFA enrollment (returns secret + QR URI)
- `POST /mfa/verify` — complete MFA enrollment with TOTP code
- `POST /mfa/challenge` — MFA challenge during login

### Operations
- `GET /health` — health check (DB + Redis)
- `GET /live` — liveness probe (always 200)
- `GET /ready` — readiness probe (DB + Redis)
- `GET /metrics` — Prometheus metrics

### Management API
- `POST /dbconnections/signup` — create user
- `POST /dbconnections/change_password` — request password reset (Auth0-style)
- **Users**
  - `GET /api/v2/users` — list users (pagination: `page`, `per_page`, `include_totals`; search: `q`)
  - `GET /api/v2/users/export` — export users (admin, paginated)
  - `POST /api/v2/users/import` — bulk import users
  - `POST /api/v2/users` — create user (connection, email, password, name, user_metadata, app_metadata)
  - `GET /api/v2/users/{id}` — user info
  - `PATCH /api/v2/users/{id}` — update user (email, name, user_metadata, app_metadata)
  - `DELETE /api/v2/users/{id}` — hard delete user (GDPR-compliant)
  - `GET /api/v2/users/{id}/export` — GDPR data export for user
  - `GET /api/v2/users/{id}/blocks` — list user blocks
  - `POST /api/v2/users/{id}/blocks` — block user
  - `DELETE /api/v2/users/{id}/blocks` — unblock user
- `GET /api/v2/users/{id}/roles` — list user roles
- `POST /api/v2/users/{id}/roles` — assign roles
- `DELETE /api/v2/users/{id}/roles` — remove roles
- `GET /api/v2/users/{id}/permissions` — list user permissions
- **Roles**
  - `GET /api/v2/roles` — list roles
  - `POST /api/v2/roles` — create role
  - `GET /api/v2/roles/{id}` — get role
  - `PATCH /api/v2/roles/{id}` — update role
  - `DELETE /api/v2/roles/{id}` — delete role
- **Clients**
  - `GET /api/v2/clients` — list clients
  - `GET /api/v2/clients/{id}` — get client
  - `PATCH /api/v2/clients/{id}` — update client (name, callbacks, allowed_origins)
- **Connections**
  - `GET /api/v2/connections` — list connections
  - `GET /api/v2/connections/{id}` — get connection
- **Logs**
  - `GET /api/v2/logs` — audit logs (`per_page` for limit)
- **Token Vault** (requires `TOKEN_VAULT_ENABLED=true`, `TOKEN_VAULT_KEY`)
  - `POST /api/v2/token-vault` — store token (name, access_token, metadata); returns vault_id (Bearer token required)
  - `GET /api/v2/token-vault/{name}` — retrieve by name (admin or token owner)

### SCIM 2.0 Provisioning API
- `GET /scim/v2/Users` — list users (filter, count, startIndex)
- `GET /scim/v2/Users/{id}` — get user
- `POST /scim/v2/Users` — create user
- `PATCH /scim/v2/Users/{id}` — partial update
- `PUT /scim/v2/Users/{id}` — replace user
- `DELETE /scim/v2/Users/{id}` — delete user
- `GET /scim/v2/Groups` — list groups (maps to roles)
- `GET /scim/v2/ResourceTypes`, `GET /scim/v2/Schemas` — discovery

Requires `Authorization: Bearer <SCIM_API_TOKEN or ADMIN_API_KEY>`. Use `application/scim+json` content-type.

## Config (env)

- `PORT` — default 9092
- `DB_PATH` — default `./data/auth0.db`
- `ISSUER_URL` — JWT issuer (e.g. `http://auth2:9092`)
- `TLS_CERT`, `TLS_KEY` — enable HTTPS
- `RULES_DIR` — directory with Auth0 Rules .js files (optional)
- `CLIENT_REGISTRY` — JSON map of client_id → {client_secret, redirect_uris, allowed_scopes}. Example: `{"my-client":{"client_secret":"secret","redirect_uris":["http://localhost/cb"],"allowed_scopes":["openid","profile"]}}`
- `ACCESS_TOKEN_LIFETIME` — access token TTL in seconds (default 86400)
- `ID_TOKEN_LIFETIME` — ID token TTL in seconds (default 86400)
- `CORS_ALLOWED_ORIGINS` — comma-separated origins for CORS (default: localhost origins for dev). Supports `*` for allow-all.
- `RATE_LIMIT_RPM` — requests per minute per IP for auth endpoints (default 100). Responses include `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers.
- `ADMIN_API_KEY` / `MGMT_API_KEY` — optional; when set, management API (`/api/v2/*`) and GraphQL test API require Bearer token
- `SCIM_API_TOKEN` — optional; when set, SCIM 2.0 provisioning API (`/scim/v2/*`) requires Bearer token. Falls back to `ADMIN_API_KEY` if unset
- `GRAPHQL_TEST_API_ENABLED` — when `true`, enables `POST /graphql` for E2E user creation
- `PRODUCTION_MODE` — when `true`, requires admin auth even if `ADMIN_API_KEY` is unset (rejects unauthenticated management requests)
- `AUDIT_STORE` — `stdout` (default) or `db`; when `db`, audit events persist to the same database
- `AUDIT_WEBHOOK_URL` — Optional; when set (with `AUDIT_STORE=db` or `stdout`), POST each audit event to this URL
- `OTEL_EXPORTER_OTLP_ENDPOINT` — Optional; when set, enable OpenTelemetry tracing (e.g. `http://localhost:4318`)

### CIBA, Token Vault, FAPI
- `TOKEN_VAULT_ENABLED` — when `true`, enables Token Vault API (`POST/GET /api/v2/token-vault`)
- `TOKEN_VAULT_KEY` — AES key for token encryption (32+ bytes raw, or `hex:` + 64 hex chars)
- `FAPI_ENABLED` — when `true`, enforces Financial-grade API: PKCE required for auth code, S256 only, response_mode query/fragment

### WebAuthn (Passkeys)
- `WEBAUTHN_ENABLED` — when `true`, enables passkey registration and passwordless login
- `WEBAUTHN_DISPLAY_NAME` — Relying Party display name (default: auth2)

### GraphQL Test API (E2E)
- `POST /graphql` — When `GRAPHQL_TEST_API_ENABLED=true`; `mutation { createUser(email, password, name?) { id email } }`; requires `Authorization: Bearer ADMIN_API_KEY`. For programmatic user creation in E2E tests. See [E2E quickstart](docs/quickstarts/E2E.md).

### Documentation

- [Deployment Guide](DEPLOY.md) — Production deployment on GCP, AWS
- [Quickstarts](docs/quickstarts/) — [React](docs/quickstarts/React.md), [Next.js](docs/quickstarts/Next.js.md), [E2E](docs/quickstarts/E2E.md)
- [Compliance](docs/COMPLIANCE.md) — GDPR, HIPAA, PCI considerations
- [Rules](docs/RULES.md) — How auth2 Rules work and example `.js` files

### Management API Auth
- **Admin API key** — Set `ADMIN_API_KEY` or `MGMT_API_KEY` to require `Authorization: Bearer <key>` on `/api/v2/*` routes. **Bootstrap:** On first-run, set `ADMIN_API_KEY` to a secure value (e.g. `openssl rand -hex 32`).
- **JWT scopes** — Alternatively, a valid JWT with `read:users`, `manage:clients`, or similar admin scopes grants access.
- **Dev mode** — When `ADMIN_API_KEY` is not set and `PRODUCTION_MODE` is not set, management routes allow unauthenticated access (for local dev).

### Sessions & Audit
- **Server-side sessions** — After login, an `auth2_session` cookie is set. `/authorize` skips the login page when the user is already authenticated.
- **Audit logging** — Login, signup, token issuance, and user changes (PATCH/DELETE) are logged. Set `AUDIT_STORE=stdout` (default) or `AUDIT_STORE=db` to persist to the database.

## Run

```bash
go run .
```

Or with Docker:

```bash
docker run -p 9092:9092 jmadler/auth2
```

## Build and push Docker image

```bash
docker build -t jmadler/auth2 .
docker push jmadler/auth2
```

Log in first with `docker login` if needed.

CI (GitHub Actions) builds and pushes on push to main. Add `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` as repo secrets.

## Admin UI

`GET /admin` — Web dashboard to manage users, clients, roles, and view audit logs. Login with `ADMIN_API_KEY`.

## Docs

- [Rules](docs/RULES.md) — Customize auth with JavaScript Rules
- [Quickstarts](docs/quickstarts/) — React, Next.js
- [Compliance](docs/COMPLIANCE.md) — GDPR, HIPAA, PCI self-hosted guidance

## Tests

```bash
go test ./...                    # unit tests
go test -tags=integration ./...   # unit + integration tests
```