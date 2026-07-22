# fake-auth Roadmap

Plan from dev mock to production-ready auth. Each section can be tackled independently.

---

## Phase 1: Security & Hardening

### Secrets & Config
- [ ] **Secret manager** — Replace `CLIENT_REGISTRY` env with Vault, AWS Secrets Manager, or file-based encrypted config
- [ ] **Sensitive env vars** — Never log `client_secret`, `password`, tokens; redact in audit
- [ ] **Config validation** — Validate CLIENT_REGISTRY JSON, redirect_uris, allowed_scopes on startup

### CORS & Headers
- [ ] **CORS whitelist** — Replace `Access-Control-Allow-Origin: *` with configurable allowed origins per client or global
- [ ] **Security headers** — Add `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`

### Rate Limiting
- [ ] **Per-IP rate limit** — Limit auth attempts (login, token, signup) per IP (e.g. 100/min)
- [ ] **Per-client rate limit** — Limit token requests per client_id
- [ ] **Brute-force protection** — Temporary lockout after N failed logins (e.g. 5 attempts)

---

## Phase 2: Database & State

### PostgreSQL
- [ ] **Postgres driver** — Add `internal/store/postgres.go` with same interface as SQLite
- [ ] **Migrations** — SQL migration files (e.g. `migrations/001_initial.sql`), version table
- [ ] **Connection pooling** — Configurable pool size, `DB_MAX_OPEN`, `DB_MAX_IDLE`
- [ ] **Env switch** — `DB_DRIVER=sqlite|postgres`, `DB_DSN` for connection string

### Shared State (for multi-instance)
- [ ] **Redis for grants** — Store auth codes, refresh tokens, device codes in Redis with TTL
- [ ] **Redis for sessions** — Replace in-memory `sessions.Store` with Redis backend
- [ ] **Optional** — Keep in-memory for single-instance dev; switch via `SESSION_STORE=memory|redis`

---

## Phase 3: Auth Features

### Email & Password
- [ ] **Email verification** — `email_verified` flag; optional verification token flow (`POST /passwordless/start` or custom)
- [ ] **Password reset** — `POST /dbconnections/change_password` or custom reset flow with time-limited token
- [ ] **Password policy** — Min length, complexity; reject weak passwords on signup
- [ ] **Account lockout** — After N failed logins, block account for X minutes; clear on success

### MFA (Multi-Factor)
- [ ] **TOTP (authenticator app)** — Generate secret, verify code; store in `user_metadata` or new table
- [ ] **MFA enrollment** — `POST /mfa/enroll`, `POST /mfa/verify` (or similar)
- [ ] **MFA challenge at login** — After password, require TOTP before issuing tokens
- [ ] **Backup codes** — Generate one-time backup codes for account recovery

### Social / Federation
- [ ] **OAuth social login** — Proxy to Google, GitHub, etc.; map `sub` to local user or create
- [ ] **SAML** — Basic SAML IdP support for enterprise SSO (optional, larger scope)

---

## Phase 4: Scalability & Operations

### Deployment
- [ ] **Health checks** — `/health` probes DB and Redis (if used); return 503 if unhealthy
- [ ] **Graceful shutdown** — Drain in-flight requests, then exit
- [ ] **Readiness vs liveness** — Separate endpoints if needed for K8s

### Observability
- [ ] **Structured logging** — JSON logs with request_id, user_id, level
- [ ] **Tracing** — OpenTelemetry or similar; trace auth flows
- [ ] **Metrics** — Extend Prometheus: error rates, latencies, active sessions

### TLS
- [ ] **TLS by default** — Require TLS_CERT/TLS_KEY in production mode
- [ ] **ACME / Let's Encrypt** — Auto-provision certs (optional)

---

## Phase 5: Management & Compliance

### Admin
- [ ] **Admin UI** — Simple web UI to list users, clients, roles; view logs
- [ ] **Admin API auth** — Management API requires `Bearer` token with `read:users`-style scopes
- [ ] **Bootstrap admin** — Initial admin user or API key for first-run setup

### Audit & Compliance
- [ ] **Audit persistence** — Store audit events in DB or dedicated log store (not just stdout)
- [ ] **Audit retention** — Configurable retention policy
- [ ] **GDPR** — `DELETE /api/v2/users/{id}` hard-deletes or anonymizes; data export endpoint

---

## Phase 6: Optional / Nice-to-Have

- [ ] **Organizations** — Multi-tenant org support (Auth0-style)
- [ ] **GraphQL test API** — Like simulacrum for programmatic user creation in tests
- [ ] **Cypress / Playwright helpers** — NPM package for E2E login helpers
- [ ] **Docker Compose** — Full stack: fake-auth + Postgres + Redis for local “prod-like” dev

---

## Implementation Order (Suggested)

1. **Phase 1** (Security) — CORS, rate limit, no logging secrets
2. **Phase 2** (DB) — Postgres + Redis for production deploy
3. **Phase 3** (Auth) — Email verification, password reset, MFA
4. **Phase 4** (Ops) — Better health, tracing, metrics
5. **Phase 5** (Admin) — Admin UI, audit persistence
6. **Phase 6** — As needed
