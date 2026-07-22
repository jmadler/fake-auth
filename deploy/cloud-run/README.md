# GCP Cloud Run Deployment

Deploy auth2 to GCP Cloud Run for serverless, autoscaling Auth0 replacement.

## Prerequisites

- Google Cloud SDK (`gcloud`) installed
- Project with Cloud Run API enabled
- Cloud SQL (PostgreSQL) instance
- Memorystore (Redis) instance (optional, for multi-instance sessions)
- Secret Manager for secrets

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | Yes | Port to listen on (Cloud Run uses 8080) |
| `DB_DSN` | Yes* | Postgres connection string. Cloud SQL: `postgres://user:pass@/dbname?host=/cloudsql/PROJECT:REGION:INSTANCE` |
| `DB_DRIVER` | No | `sqlite` (default) or `postgres` when Postgres support is added |
| `DB_PATH` | No | SQLite path when using `DB_DRIVER=sqlite` (not recommended for Cloud Run) |
| `REDIS_URL` | No | Memorystore Redis URL for session/grant storage: `redis://host:6379` |
| `ISSUER_URL` | Yes | Public base URL, e.g. `https://auth2.YOUR_DOMAIN.run.app` |
| `CLIENT_REGISTRY` | No | JSON map of client_id -> {client_secret, redirect_uris, allowed_scopes} |

\* When Postgres is implemented. Until then, use SQLite with a volume (ephemeral) or wait for Postgres support.

## Secrets Setup

```bash
# DB DSN (Cloud SQL Postgres)
echo -n "postgres://user:password@/authdb?host=/cloudsql/PROJECT:us-central1:INSTANCE" | \
  gcloud secrets create auth2-db-dsn --data-file=-

# Redis URL (Memorystore)
echo -n "redis://10.x.x.x:6379" | \
  gcloud secrets create auth2-redis-url --data-file=-
```

## Deploy

### Build and deploy manually

```bash
# Build and push
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/auth2

# Deploy (replace YOUR_PROJECT_ID and set env vars)
gcloud run deploy auth2 \
  --image gcr.io/YOUR_PROJECT_ID/auth2:latest \
  --region us-central1 \
  --platform managed \
  --port 8080 \
  --min-instances 0 \
  --max-instances 10 \
  --set-env-vars "PORT=8080,ISSUER_URL=https://auth2-xxx.run.app" \
  --update-secrets "DB_DSN=auth2-db-dsn:latest,REDIS_URL=auth2-redis-url:latest"
```

### Using Cloud Build

```bash
gcloud builds submit --config=deploy/cloud-run/cloudbuild.yaml .
```

## Health Checks

- **Path:** `/health`
- Returns `{"status":"ok"}` when healthy
- Startup and liveness probes use this endpoint
