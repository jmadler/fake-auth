# Changelog

All notable changes to auth2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OAuth 2.0 / OIDC: authorization code, implicit, password, client_credentials, refresh token, device code
- PKCE support
- Management API: users, roles, clients, connections (Auth0-compatible)
- MFA: TOTP, backup codes, enrollment, challenge
- Social login: Google, GitHub
- Passwordless: magic link, SMS OTP
- Password reset, email verification, breached password detection
- Rate limiting: per-IP, per-client, suspicious IP throttling
- Bot detection
- ACL (Tenant Access Control): allow/deny by path, IP, client_id
- ACME / Let's Encrypt auto-provisioning
- Admin UI at `/admin`
- GraphQL test API for E2E
- Structured logging, OpenTelemetry tracing, Prometheus metrics
- Health checks: `/health`, `/live`, `/ready`
- PostgreSQL and Redis backends
- Docker Compose stack
- E2E helpers (Cypress, Playwright)
- Custom login template (`LOGIN_PAGE_TEMPLATE`)

### Security

- CORS whitelist, security headers (HSTS, X-Frame-Options, etc.)
- TLS by default in production mode
- Audit logging with redaction of sensitive fields

## [0.1.0] - TBD

Initial release.
