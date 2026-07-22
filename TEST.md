# auth2 Testing Strategy

We follow the **test pyramid**: many fast unit tests at the base, fewer integration tests, and minimal end-to-end tests at the top.

---

## Pyramid Overview

```
        ┌─────────┐
        │   E2E   │  Few: full stack, Cypress/Playwright
        │  tests  │  Manual or CI, slow
        └────┬────┘
             │
      ┌──────┴──────┐
      │ Integration│  Moderate: HTTP server, real DB/Redis
      │    tests   │  go test -tags=integration
      └──────┬──────┘
             │
   ┌─────────┴─────────┐
   │     Unit tests    │  Many: fast, isolated, mock deps
   │  (package _test)  │  go test ./...
   └───────────────────┘
```

---

## 1. Unit Tests (Base)

**Goal:** Fast feedback, high coverage of logic. Mock external deps (DB, HTTP, Redis) where practical.

**Where:** `*_test.go` next to source; package `packagename` or `packagename_test`.

**Run:** `go test ./...` (excludes integration by default)

**Examples:**
- `internal/botdetect` — IsBot, middleware (blocks empty UA, crawlers)
- `internal/ratelimit` — Allow, Status, FailedAttemptTracker, suspicious IP, client limiter, auth result recording, X-Forwarded-For/X-Real-IP
- `internal/acl` — Rule matching, path/IP/client_id/CIDR, LoadFromEnv (inline/file), Middleware
- `internal/password` — Validate, IsBreached
- `internal/mfa` — TOTP, backup codes
- `internal/sms` — SendOTP (no provider), IsConfigured
- `internal/email` — LoadFromEnv, SendMagicLink (nil config)
- `internal/handlers` — Individual handler behavior (testHandlers helper), custom login template
- `internal/graphql` — createUser mutation, unauthorized, invalid password
- `internal/fapi` — Enabled, ValidateFAPIRequest (PKCE, response_mode)
- `internal/scim` — Handler routes, AuthMiddleware, list/create/get users
- `internal/enterprise` — NewProvider, Name
- `internal/tokenvault` — Encrypt/Decrypt roundtrip, Enabled
- `internal/saml` — DecodeSAMLRequest, ParseAuthnRequest, BuildMetadata
- `internal/cors` — Middleware, parseAllowedOrigins, OPTIONS, Origin matching
- `internal/securityheaders` — Middleware (HSTS when TLS)
- `internal/metrics` — Middleware, sanitizePath
- `internal/social` — GetProvider, RegisterProvider, google-oauth2 alias
- `internal/webauthn` — New (disabled)
- `internal/adminui` — NewHandler, login, auth redirect
- `internal/store` — ListUsers, CRUD users/roles/clients, password reset, magic link, MFA, WebAuthn, orgs, SAML SP, OIDC enterprise, invitations, org connections, provider identity, failed login/lockout, SMS OTP, known IPs, audit logs export

---

## 2. Integration Tests (Middle)

**Goal:** Verify components work together over HTTP. Real SQLite, in-memory grants/sessions.

**Where:** `integration_test.go` (root). Build tag: `//go:build integration`

**Run:** `go test -tags=integration ./...`

**Setup:** `setupIntegrationServer` spins up HTTP server with SQLite, seed user, grants store.

**Examples:**
- Health, live, ready, metrics
- OAuth: password, auth code, refresh, revoke, introspect
- Management API: users CRUD, clients, roles
- Magic link flow
- MFA enroll/verify/challenge
- ACL: deny /oauth/token, allow other paths
- Custom login template (LOGIN_PAGE_TEMPLATE)
- GraphQL createUser (with ADMIN_API_KEY)
- SCIM: list, create, get users
- Organizations: create, list, add members

---

## 3. E2E Tests (Top)

**Goal:** Full user journey in real browser. auth2 + DB + Redis + app.

**Where:** `e2e-helpers/` NPM package; Cypress/Playwright specs (separate repo or `e2e/`).

**Run:** `npm run test:e2e` or CI pipeline. Not part of `go test`.

---

## Coverage Targets

- **Unit:** Aim for >80% on core packages. Current: acl (80%), ratelimit (80%), mfa (90%), rules (81%). Store and handlers are larger; store ~42% (SQLite covered, Postgres untested); handlers ~35%.
- **Integration:** Cover all HTTP endpoints and major flows. No strict % target.

---

## Running Tests

```bash
# Unit only (default)
go test ./...

# With coverage
go test -cover ./...

# Integration (includes unit)
go test -tags=integration ./...

# Short unit run (skip slow)
go test -short ./...
```

---

## Adding New Tests

1. **New package:** Add `packagename_test.go` with unit tests.
2. **New HTTP flow:** Add `TestIntegrationX` in `integration_test.go`; use `setupIntegrationServer`.
3. **New E2E flow:** Add to `e2e-helpers` examples or Cypress/Playwright spec.
