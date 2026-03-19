# fake-auth

Auth0-compatible mock for local development. Stores users in SQLite and issues RS256 JWTs.

## Endpoints

### OAuth/OIDC
- `GET /authorize` — authorization code, implicit (`response_type=token` / `id_token`), PKCE (`code_challenge`), `audience`
- `GET /login` — login page for browser-based auth
- `POST /login` — submit credentials for auth code or implicit flow
- `POST /oauth/token` — token endpoint
  - `grant_type=password` / `password-realm` — resource owner password
  - `grant_type=client_credentials` — client credentials
  - `grant_type=authorization_code` — exchange code for tokens (PKCE with `code_verifier`)
  - `grant_type=refresh_token` — refresh with token rotation
  - `grant_type=urn:ietf:params:oauth:grant-type:device_code` — device code flow
- `POST /oauth/revoke` — revoke refresh or access token
- `POST /oauth/introspect` — RFC 7662 token introspection
- `POST /oauth/device/code` — request device code (client_id, scope, audience)
- `GET /oauth/device/authorize` — user enters code and authenticates
- `GET /userinfo` — OIDC userinfo (Bearer token)
- `POST /tokeninfo` — Auth0 legacy token introspection
- `GET /.well-known/jwks.json` — JWKS
- `GET /.well-known/openid-configuration` — OIDC discovery (includes `revocation_endpoint`, `introspection_endpoint`)
- `GET /v2/logout` — logout (redirect to `returnTo` or `post_logout_redirect_uri`)

### Operations
- `GET /health` — health check (returns `{"status":"ok"}`)
- `GET /metrics` — Prometheus metrics (authorize/token/login counters)

### Management API
- `POST /dbconnections/signup` — create user
- **Users**
  - `GET /api/v2/users` — list users (pagination: `page`, `per_page`, `include_totals`; search: `q`)
  - `POST /api/v2/users` — create user (connection, email, password, name, user_metadata, app_metadata)
  - `GET /api/v2/users/{id}` — user info
  - `PATCH /api/v2/users/{id}` — update user (email, name, user_metadata, app_metadata)
  - `DELETE /api/v2/users/{id}` — delete user
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

## Config (env)

- `PORT` — default 9092
- `DB_PATH` — default `./data/auth0.db`
- `ISSUER_URL` — JWT issuer (e.g. `http://fake-auth:9092`)
- `SEED_USERS_PATH` — path to JSON config file to seed users at startup. Format: `{"users":[{"id":"auth0|...","email":"...","password":"...","display_name":"...","role":"..."}]}`. Idempotent (INSERT OR IGNORE).
- `TLS_CERT`, `TLS_KEY` — enable HTTPS
- `RULES_DIR` — directory with Auth0 Rules .js files (optional)
- `CLIENT_REGISTRY` — JSON map of client_id → {client_secret, redirect_uris, allowed_scopes}. Example: `{"my-client":{"client_secret":"secret","redirect_uris":["http://localhost/cb"],"allowed_scopes":["openid","profile"]}}`
- `ACCESS_TOKEN_LIFETIME` — access token TTL in seconds (default 86400)
- `ID_TOKEN_LIFETIME` — ID token TTL in seconds (default 86400)

### Sessions & Audit
- **Server-side sessions** — After login, a `fake_auth_session` cookie is set. `/authorize` skips the login page when the user is already authenticated.
- **Audit logging** — Login, signup, token issuance, and user changes (PATCH/DELETE) are logged to stdout as JSON (prefix `[audit]`).

## Run

```bash
go run .
```

Or with Docker:

```bash
docker run -p 9092:9092 jmadler/fake-auth
```

## Build and push Docker image

```bash
docker build -t jmadler/fake-auth .
docker push jmadler/fake-auth
```

Log in first with `docker login` if needed.

CI (GitHub Actions) builds and pushes on push to main. Add `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` as repo secrets.

## Tests

```bash
go test ./...                    # unit tests (handlers, store, etc.)
go test -tags=integration ./...  # unit + integration tests (OAuth flows, SeedFromConfig)
```