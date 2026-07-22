# auth2 Deployment Guide

Production deployment options for auth2 (Auth0 replacement) on GCP Cloud Run and AWS.

## Quick Start (Local)

Run a prod-like stack locally with Docker Compose:

```bash
docker compose -f deploy/docker-compose.yml up -d
```

- **auth2:** http://localhost:9092
- **Health:** http://localhost:9092/health
- **Postgres:** localhost:5432 (user: auth2, db: auth2)
- **Redis:** localhost:6379

---

## GCP Cloud Run

[Full docs](deploy/cloud-run/README.md)

### Deploy

```bash
# Build and push
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/auth2

# Deploy
gcloud run deploy auth2 \
  --image gcr.io/YOUR_PROJECT_ID/auth2:latest \
  --region us-central1 \
  --platform managed \
  --port 8080 \
  --min-instances 0 \
  --max-instances 10 \
  --set-env-vars "PORT=8080,ISSUER_URL=https://auth2-xxx.run.app"
```

### Env vars

| Variable | Description |
|----------|-------------|
| `DB_DSN` | Cloud SQL Postgres (use Secret Manager) |
| `REDIS_URL` | Memorystore Redis (use Secret Manager) |
| `ISSUER_URL` | Public base URL |
| `PORT` | 8080 (Cloud Run default) |

### Health checks

| Path | Use | Description |
|------|-----|-------------|
| `/health` | Backward compat | Same as `/ready` — DB+Redis checks |
| `/ready` | K8s readinessProbe | DB+Redis ping; 503 if not ready |
| `/live` | K8s livenessProbe | Always 200 if process is up |

- **Liveness:** `GET /live` — minimal check (process responding)
- **Readiness:** `GET /ready` — checks DB and Redis (if used)

---

## AWS

[Full docs](deploy/aws/README.md)

### ECS Fargate

1. Build and push to ECR
2. Create secrets in Secrets Manager (`DB_DSN`, `REDIS_URL`)
3. Register task definition: `aws ecs register-task-definition --cli-input-json file://deploy/aws/ecs-task-definition.json`
4. Create ECS service with ALB; health check path: `/health`

### App Runner

1. Build and push to ECR
2. Create service: `aws apprunner create-service --cli-input-json file://deploy/aws/apprunner-service.json`
3. Health checks use `/health` automatically

### Infrastructure

- **RDS PostgreSQL** — user database
- **ElastiCache Redis** — sessions and grants (GRANT_STORE=redis, SESSION_STORE=redis)
- **ALB** — health check `/health`, 30s interval

---

## Environment Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 9092 | Listen port |
| `DB_PATH` | ./data/auth0.db | SQLite path (when DB_DRIVER=sqlite) |
| `DB_DRIVER` | sqlite | `sqlite` \| `postgres` |
| `DB_DSN` | — | Postgres connection string |
| `DB_MAX_OPEN` | 25 | Max open DB connections (Postgres) |
| `DB_MAX_IDLE` | 5 | Max idle DB connections (Postgres) |
| `GRANT_STORE` | memory | `memory` \| `redis` |
| `SESSION_STORE` | memory | `memory` \| `redis` |
| `REDIS_URL` | — | Redis URL (required for redis stores) |
| `ISSUER_URL` | http://localhost:PORT | JWT issuer base URL |
| `CLIENT_REGISTRY` | — | JSON client config map |
| `CLIENT_REGISTRY_FILE` | — | Path to client config JSON file (takes precedence over CLIENT_REGISTRY) |
| `CLIENT_REGISTRY_KEY` | — | Optional: 32-byte hex key for AES-256-GCM decryption of encrypted file |
| `AUDIT_STORE` | stdout | `stdout` \| `db` — persist audit logs to database |
| `AUDIT_RETENTION_DAYS` | 90 | When AUDIT_STORE=db, delete logs older than N days |
| `ADMIN_API_KEY` | — | Bearer token for management API auth |
| `MGMT_API_KEY` | — | Alias for ADMIN_API_KEY |
| `SCIM_API_TOKEN` | — | Bearer token for SCIM 2.0 provisioning (`/scim/v2/*`). Falls back to `ADMIN_API_KEY` if unset |
| `LOG_FORMAT` | text | `json` \| `text` — structured logging format |
| `RATE_LIMIT_RPM` | 100 | Per-IP requests per minute |
| `RATE_LIMIT_CLIENT_RPM` | 200 | Per-client_id requests per minute (token, device code) |
| `AUDIT_WEBHOOK_URL` | — | POST each audit event (JSON) to this URL when `AUDIT_STORE` is `db` or `stdout` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTLP endpoint for OpenTelemetry traces (e.g. `http://localhost:4318`) |
| `MAGIC_LINK_DEV_RETURN_TOKEN` | false | When true, `POST /passwordless/start` returns token in response (for dev/testing without email) |
| `SMTP_HOST` | — | SMTP server host (e.g. `smtp.example.com` or `smtp.example.com:587`) for magic link emails |
| `SMTP_USER` | — | SMTP auth username |
| `SMTP_PASS` | — | SMTP auth password |
| `SMTP_FROM` | — | From address for magic link emails (defaults to SMTP_USER if empty) |
| `BREACHED_PASSWORD_CHECK` | false | When `true`, reject signup/password-reset if password found in HIBP breach DB |
| `BREACHED_PASSWORD_CHECK_TIMEOUT` | 10 | Timeout in seconds for HIBP API calls |
| `PRODUCTION_MODE` | false | When `true` (or `PRODUCTION=true`), require TLS; exit if missing (TLS_CERT/TLS_KEY or ACME) |
| `PRODUCTION` | — | Alias for PRODUCTION_MODE |
| `TLS_CERT` | — | Path to TLS certificate file (ignored when ACME enabled) |
| `TLS_KEY` | — | Path to TLS private key file (ignored when ACME enabled) |
| `TLS_ACME_ENABLED` | false | When `true`, use Let's Encrypt to auto-provision certs via `golang.org/x/crypto/acme/autocert` |
| `TLS_ACME_DOMAIN` | — | Domain for ACME cert (required when TLS_ACME_ENABLED=true). HostPolicy allows only this domain |
| `TLS_ACME_EMAIL` | — | Contact email for Let's Encrypt (recommended) |
| `TLS_ACME_CACHE_DIR` | ./certs | Directory to cache ACME-obtained certificates |
| `TLS_ACME_HTTP_PORT` | — | When set (e.g. 80), run HTTP-01 challenge server for Let's Encrypt validation |
| `ACL_RULES` | — | Inline JSON array of ACL rules: `[{action:"allow"|"deny", path:"/oauth/*", ip:"1.2.3.0/24", client_id:"x"}]` |
| `ACL_RULES_FILE` | — | Path to JSON file with ACL rules (takes precedence over ACL_RULES). Default also checks `acl_rules.json` |
| `LOGIN_PAGE_TEMPLATE` | — | Path to custom login HTML template (Go template with .ClientID, .RedirectURI, etc.) |
| `BOT_DETECTION_ENABLED` | false | When `true`, block obvious bots (empty User-Agent, crawler patterns) with 403 |
| `SUSPICIOUS_IP_FAILED_THRESHOLD` | 5 | Failed auth attempts per IP before applying strict throttle |
| `SUSPICIOUS_IP_STRICT_RPM` | 5 | Requests/min for IPs over failed threshold |
| `MFA_ENABLED` | false | Enable MFA endpoints and password-grant MFA challenge |
| `ADAPTIVE_MFA_ENABLED` | false | When `true` with MFA_ENABLED, only require MFA for new IP/session (risky login) |
| `SMS_OTP_DEV_RETURN_CODE` | false | When `true`, `POST /passwordless/start` (auth_type=sms) returns OTP in response |
| `TWILIO_ACCOUNT_SID` | — | Twilio Account SID for SMS OTP |
| `TWILIO_AUTH_TOKEN` | — | Twilio Auth Token |
| `TWILIO_FROM` | — | Twilio From number or Messaging Service SID |
| `GRAPHQL_TEST_API_ENABLED` | false | When `true`, enable `POST /graphql` for E2E test user creation (requires ADMIN_API_KEY) |
