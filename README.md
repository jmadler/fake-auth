# fake-auth0

Auth0-compatible mock for local development. Stores users in SQLite and issues RS256 JWTs.

## Endpoints

- `POST /oauth/token` — password grant, password-realm, client_credentials
- `POST /dbconnections/signup` — create user
- `GET /api/v2/users/{id}` — user info
- `PATCH /api/v2/users/{id}` — update user (stub)
- `GET/DELETE/POST /api/v2/users/{id}/roles` — role stubs (204)
- `GET /.well-known/jwks.json` — JWKS
- `GET /.well-known/openid-configuration` — OIDC discovery

## Config (env)

- `PORT` — default 9092
- `DB_PATH` — default `./data/auth0.db`
- `ISSUER_URL` — JWT issuer (e.g. `http://fake-auth0:9092`)

## Run

```bash
go run .
```

Or with Docker (see [radimal-dev](https://github.com/radimal/radimal-dev) compose).