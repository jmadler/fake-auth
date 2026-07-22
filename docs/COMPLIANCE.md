# auth2 Self-Hosted Compliance

auth2 is a self-hosted authentication platform. You control where data lives and how it is processed. This document outlines compliance considerations when self-hosting auth2.

---

## Availability & SLA

**99.99% uptime** — Auth0 advertises 99.99% monthly uptime. With auth2, you control infrastructure:

- Deploy to managed platforms (GCP Cloud Run, AWS ECS) with auto-restart and multi-zone
- Use health checks (`/health`, `/ready`, `/live`) for load balancers and orchestrators
- Run multiple instances behind a load balancer (Redis for shared state)
- Set up monitoring and alerting on your SLA targets
- Your cloud provider's SLA (e.g. GCP 99.95%) applies; add redundancy for higher targets

---

## Data Residency

**You control it.** auth2 runs in your infrastructure (GCP, AWS, on-premises). All user data, audit logs, and tokens are stored in databases you manage (PostgreSQL or SQLite) and optionally in Redis. There is no data sent to third-party SaaS providers by default.

- Choose your deployment region (e.g. `europe-west1` for EU)
- Use region-specific RDS/Cloud SQL / Redis
- No cross-border transfer unless you configure it

---

## Audit Logs

### Enabling audit persistence

Set `AUDIT_STORE=db` to persist audit events to your database. Set `AUDIT_RETENTION_DAYS` (default 90) to control retention.

```bash
AUDIT_STORE=db
AUDIT_RETENTION_DAYS=365
```

### What is logged

- Login attempts (success/failure)
- Signups
- Token issuance (grant type, client_id)
- User changes (PATCH, DELETE)
- Sensitive fields (passwords, tokens, secrets) are **redacted**

### Retention and cleanup

- Old logs are pruned on startup and daily
- Configure `AUDIT_RETENTION_DAYS` per your policy
- Access logs via Management API: `GET /api/v2/logs`

### Log streaming (webhook)

Set `AUDIT_WEBHOOK_URL` to POST each audit event to an external system (e.g. Splunk, Datadog, SIEM). Fire-and-forget; does not block request handling.

---

## GDPR

### Right to erasure (delete)

- `DELETE /api/v2/users/{id}` permanently removes the user and associated data
- Audit logs may retain references for compliance; consider anonymization policies

### Right to data portability (export)

- `GET /api/v2/users/{id}/export` returns user data in a portable format for GDPR Article 20
- Includes user metadata, app metadata, and identity information

### Data minimization

- auth2 stores only what you configure (email, name, metadata)
- Sensitive values are redacted in audit logs
- Configure `allowed_scopes` per client to limit token claims

---

## HIPAA (Healthcare)

auth2 does not provide a HIPAA BAA. For HIPAA-covered deployments:

### Suggestions

1. **Encryption at rest** — Use encrypted storage for your database (e.g. RDS encryption, Cloud SQL encryption)
2. **Encryption in transit** — Use TLS (`TLS_CERT`, `TLS_KEY` or reverse proxy) for all auth2 traffic
3. **BAA with infrastructure provider** — Ensure your cloud provider (AWS, GCP) offers a BAA for the services hosting auth2
4. **Access controls** — Use `ADMIN_API_KEY` and restrict Management API access
5. **Audit logs** — Enable `AUDIT_STORE=db` and retain per policy; stream to a HIPAA-compliant SIEM via `AUDIT_WEBHOOK_URL`

auth2 handles authentication and authorization only. PHI in your application layer remains your responsibility.

---

## PCI DSS

### Payment card data

- **auth2 does not store payment card data.** Authentication (passwords, tokens, sessions) is out of scope for PCI cardholder data.
- If your application processes payments, keep card data out of auth2; use a PCI-compliant payment processor (Stripe, etc.)

### Authentication scope

auth2 provides:

- Password storage (bcrypt)
- Token issuance (JWT)
- Session management

These align with PCI requirements for strong authentication. Ensure your deployment (TLS, access controls, audit logs) meets your organization’s PCI controls.

---

## Summary

| Topic      | auth2 support                                 |
|-----------|-----------------------------------------------|
| Data residency | You control; deploy in your region         |
| Audit logs    | `AUDIT_STORE=db`, `AUDIT_RETENTION_DAYS`   |
| GDPR delete   | `DELETE /api/v2/users/{id}`                |
| GDPR export   | `GET /api/v2/users/{id}/export`            |
| HIPAA        | Encrypt at rest, TLS, BAA with infra       |
| PCI          | No card data; auth out of scope            |
