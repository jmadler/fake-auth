# auth2 Roadmap

Drop-in Auth0 replacement. Plan from MVP to feature parity. Auth0 feature gaps noted per phase.

---

## Auth0 Feature Comparison (Research Summary)

### Auth0 Pricing (Reference)
- **Free:** Up to 25K MAU, 1 Enterprise Connection, community support
- **Essentials:** $35/mo, up to 500 MAU
- **Professional:** $240/mo, enhanced attack protection, enterprise MFA
- **Enterprise:** Custom, 99.99% SLA, private deployment

### Auth0 Key Features (from auth0.com)
- Universal Login, SSO, MFA, Actions, M2M, Passwordless
- Breached password detection, bot detection
- Organizations (multi-tenant), SCIM, Enterprise Connections
- Custom domains, Forms, Marketplace
- Token Vault, CIBA, FAPI for regulated industries
- HIPAA BAA, PCI compliance add-ons

---

## Phase 1: Security & Hardening ✅

### Secrets & Config
- [x] **Secret manager** — `CLIENT_REGISTRY_FILE`; optional `CLIENT_REGISTRY_KEY` (AES) for encrypted file
- [x] **Sensitive env vars** — Never log `client_secret`, `password`, tokens; redact in audit
- [x] **Config validation** — Validate CLIENT_REGISTRY JSON, redirect_uris, allowed_scopes on startup

### CORS & Headers
- [x] **CORS whitelist** — Configurable allowed origins per client or global
- [x] **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`

### Rate Limiting
- [x] **Per-IP rate limit** — Limit auth attempts per IP (RATE_LIMIT_RPM)
- [x] **Per-client rate limit** — Limit token requests per client_id
- [x] **Brute-force protection** — Temporary lockout after N failed logins (BRUTE_FORCE_*)

### Auth0 Gaps (Phase 1)
- [x] **Breached password detection** — HIBP k-anonymity API (`BREACHED_PASSWORD_CHECK=true`)
- [x] **Bot detection** — `BOT_DETECTION_ENABLED=true`; blocks obvious bots (403)
- [x] **Suspicious IP throttling** — `SUSPICIOUS_IP_*`; stricter limit after N failed attempts

---

## Phase 2: Database & State ✅

### PostgreSQL
- [x] **Postgres driver** — `internal/store/postgres.go` with same interface as SQLite
- [x] **Migrations** — SQL migration files, schema_migrations table
- [x] **Connection pooling** — DB_MAX_OPEN, DB_MAX_IDLE
- [x] **Env switch** — DB_DRIVER=sqlite|postgres, DB_DSN

### Shared State
- [x] **Redis for grants** — Auth codes, refresh tokens, device codes in Redis
- [x] **Redis for sessions** — SESSION_STORE=memory|redis
- [x] **Optional** — GRANT_STORE, SESSION_STORE env switch

### Auth0 Gaps (Phase 2)
- [x] **User import/export** — `POST /api/v2/users/import`, `GET /api/v2/users/export` for bulk migration
- [x] **Log retention** — `AUDIT_RETENTION_DAYS` (default 90); cleanup on startup + daily

---

## Phase 3: Auth Features ✅

### Email & Password ✅
- [x] **Email verification** — `email_verified` flag; verification flow
- [x] **Password reset** — `/dbconnections/change_password`, `/passwordless/reset`, `/passwordless/confirm`
- [x] **Password policy** — Min length, complexity; reject weak passwords
- [x] **Account lockout** — BRUTE_FORCE_MAX_ATTEMPTS, BRUTE_FORCE_LOCKOUT_MINUTES

### MFA (Multi-Factor) — Auth0 has TOTP, backup codes, Adaptive MFA
- [x] **TOTP (authenticator app)** — `internal/mfa/totp.go`; store in `mfa_enrollment` table
- [x] **MFA enrollment** — `POST /mfa/enroll`, `POST /mfa/verify`; returns secret + QR URI
- [x] **MFA challenge at login** — `POST /mfa/challenge`; required before tokens when MFA_ENABLED
- [x] **Backup codes** — One-time recovery codes; `internal/mfa/backup.go`
- [x] **Adaptive MFA** — Risk-based MFA trigger (ADAPTIVE_MFA_ENABLED); only require MFA when risky (new IP, no session)

### Passwordless — Auth0 feature
- [x] **Magic link** — Email-based passwordless login (`POST /passwordless/start`, `GET /passwordless/verify`)
- [x] **SMS OTP** — Phone-based (`auth_type=sms`; Twilio or generic SMS_API_URL; SMS_OTP_DEV_RETURN_CODE for dev)
- [x] **Passkeys / WebAuthn** — `POST /webauthn/register/begin|finish`, `POST /webauthn/assertion/begin|finish`; `connection=webauthn` on `/authorize`

### Social / Federation — Auth0 differentiator
- [x] **OAuth social login** — Google, GitHub; `internal/social/`; `connection=google|github` on `/authorize`
- [x] **SAML IdP** — `GET /.well-known/saml-metadata`, `GET|POST /saml/sso`; `POST /api/v2/saml/sp` to register SPs
- [x] **Enterprise connections** — Okta, Azure AD via OIDC; `GET /login/enterprise?connection=`
- [x] **Self-service SSO** — End users add IdP via org connections (`enterprise_connections` table)

---

## Phase 4: Scalability & Operations ✅

### Deployment ✅
- [x] **Health checks** — `/health` probes DB and Redis
- [x] **Graceful shutdown** — Drain in-flight requests
- [x] **Readiness vs liveness** — Separate `/ready` vs `/live` for K8s

### Observability
- [x] **Structured logging** — JSON logs with request_id, user_id, level
- [x] **Tracing** — OpenTelemetry (`OTEL_EXPORTER_OTLP_ENDPOINT`)
- [x] **Metrics** — Prometheus (auth2_* counters); extended with latencies (auth2_request_duration_seconds), active sessions (auth2_active_sessions)

### TLS
- [x] **TLS by default** — Require TLS_CERT/TLS_KEY when PRODUCTION_MODE=true
- [x] **ACME / Let's Encrypt** — `TLS_ACME_ENABLED`, `TLS_ACME_DOMAIN` (autocert)

### Auth0 Gaps (Phase 4)
- [x] **99.99% SLA** — Documented in docs/COMPLIANCE.md; self-hosted infra control
- [x] **Log streaming** — `AUDIT_WEBHOOK_URL` for webhook POST of audit events

---

## Phase 5: Management & Compliance ✅

### Admin ✅
- [x] **Admin API auth** — ADMIN_API_KEY, JWT scopes for `/api/v2/*`
- [x] **Bootstrap admin** — Document ADMIN_API_KEY setup
- [x] **Admin UI** — Web UI to list users, clients, roles; view logs (Auth0 has Dashboard)

### Audit & Compliance ✅
- [x] **Audit persistence** — AUDIT_STORE=stdout|db
- [x] **Audit retention** — AUDIT_RETENTION_DAYS; cleanup on startup + 24h
- [x] **GDPR delete** — `DELETE /api/v2/users/{id}` hard-deletes
- [x] **Data export** — `GET /api/v2/users/{id}/export` for GDPR portability

### Auth0 Gaps (Phase 5)
- [x] **Auth0 Dashboard parity** — Admin UI at `/admin`
- [x] **Tenant Access Control List** — `ACL_RULES` or `ACL_RULES_FILE`; allow/deny by path, IP, client_id
- [x] **HIPAA BAA / PCI** — Documented in `docs/COMPLIANCE.md`

---

## Phase 6: Auth0 Differentiators ✅

### Organizations (Auth0 B2B)
- [x] **Multi-tenant org support** — Organizations with separate connections
- [x] **Self-service SSO** — End users add their IdP
- [x] **SCIM** — `GET/POST/PATCH/PUT/DELETE /scim/v2/Users`, `/scim/v2/Groups`; `SCIM_API_TOKEN` env

### Extensibility
- [x] **Actions / Rules** — auth2 has Rules (JS); documented in `docs/RULES.md`
- [x] **Forms** — `LOGIN_PAGE_TEMPLATE`; custom Go template for login page
- [ ] **Marketplace** — Auth0 integrations; low priority (deferred)

### Developer Experience
- [x] **Docker Compose** — Full stack for local dev
- [x] **Quickstarts** — `docs/quickstarts/React.md`, `docs/quickstarts/Next.js.md`, `docs/quickstarts/E2E.md`
- [x] **Cypress / Playwright helpers** — NPM package `auth2-e2e-helpers` for E2E login
- [x] **GraphQL test API** — `POST /graphql` when `GRAPHQL_TEST_API_ENABLED=true`; create users for E2E

### Auth0 AI / Advanced
- [x] **Token Vault** — `POST /api/v2/token-vault`, `GET /api/v2/token-vault/{name}`; `TOKEN_VAULT_ENABLED`, `TOKEN_VAULT_KEY`
- [x] **CIBA** — `POST /oauth/ciba/request`, `GET /ciba/verify`, `grant_type=urn:openid:params:grant-type:ciba`
- [x] **FAPI / Highly Regulated** — `FAPI_ENABLED=true` requires PKCE, strict algorithms

---

## Implementation Priority (Suggested)

1. ~~**MFA (TOTP)**~~ — Done
2. ~~**Social login**~~ — Done (Google, GitHub)
3. ~~**Admin UI**~~ — Done at /admin
4. ~~**Structured logging + Tracing**~~ — Done (OpenTelemetry)
5. ~~**Organizations**~~ — Done (B2B / multi-tenant)
6. ~~**Passkeys, SAML, SCIM, CIBA, Token Vault, FAPI**~~ — Done

---

## Auth0 Migration Checklist (for website)

- [x] Same OAuth/OIDC endpoints (`/authorize`, `/oauth/token`, `/.well-known/*`)
- [x] Management API compatibility (`/api/v2/users`, clients, roles)
- [x] RS256 JWTs, JWKS, token introspection
- [x] Authorization code, implicit, password, client_credentials, refresh, device code
- [x] PKCE, CORS, security headers
- [x] Social connectors — Google, GitHub via `connection=google|github`
- [x] Rules → auth2 Rules (JS files in RULES_DIR); see `docs/RULES.md`
- [x] Custom domains — TLS_CERT/TLS_KEY or reverse proxy with TLS
