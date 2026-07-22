# Build stage
FROM golang:1.24-alpine AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o auth2 .

# Final stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates && \
    addgroup -g 1000 auth2 && adduser -D -u 1000 -G auth2 auth2 && \
    mkdir -p /data && chown auth2:auth2 /data

WORKDIR /app
COPY --from=build /app/auth2 .
RUN chown auth2:auth2 auth2

USER auth2

# Environment variables (override at runtime)
ENV PORT=9092
ENV DB_PATH=/data/auth0.db
# For Postgres (when DB_DRIVER=postgres): DB_DSN="postgres://user:pass@host:5432/dbname?sslmode=require"
# For Redis (when SESSION_STORE=redis): REDIS_URL="redis://host:6379"
# ISSUER_URL: JWT issuer base URL, e.g. https://auth2.example.com
# CLIENT_REGISTRY: JSON map of client_id -> {client_secret, redirect_uris, allowed_scopes}

EXPOSE 9092
CMD ["./auth2"]
