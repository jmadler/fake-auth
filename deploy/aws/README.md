# AWS Deployment

Deploy auth2 to AWS via ECS Fargate or App Runner.

## Architecture

| Component | AWS Service |
|-----------|-------------|
| Compute | ECS Fargate or App Runner |
| Database | RDS PostgreSQL |
| Cache/Sessions | ElastiCache Redis |
| Load Balancer | ALB (ECS) or App Runner managed |
| Secrets | Secrets Manager or SSM Parameter Store |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | Yes | Port to listen on (default 8080) |
| `DB_DSN` | Yes* | RDS Postgres: `postgres://user:pass@host:5432/dbname?sslmode=require` |
| `DB_DRIVER` | No | `sqlite` or `postgres` when Postgres is implemented |
| `REDIS_URL` | No | ElastiCache Redis: `redis://elasticache-endpoint:6379` |
| `ISSUER_URL` | Yes | Public base URL, e.g. `https://auth.example.com` |
| `CLIENT_REGISTRY` | No | JSON map of client configs |

## ECS Fargate

### Prerequisites

- ECR repository: `auth2`
- ECS cluster
- VPC with public/private subnets
- Application Load Balancer (ALB) for health checks
- RDS PostgreSQL instance (in same VPC)
- ElastiCache Redis (optional)

### Task Definition

1. Edit `ecs-task-definition.json`:
   - Replace `ACCOUNT_ID` and `REGION`
   - Update `executionRoleArn` and `taskRoleArn`
   - Update `image` to your ECR URI
   - Add VPC config when creating service

2. Create secrets in Secrets Manager:
   ```bash
   aws secretsmanager create-secret --name auth2/db-dsn \
     --secret-string "postgres://user:pass@rds-endpoint:5432/authdb?sslmode=require"
   aws secretsmanager create-secret --name auth2/redis-url \
     --secret-string "redis://elasticache-endpoint:6379"
   ```

3. Create task definition:
   ```bash
   aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json
   ```

4. Create ECS service with ALB, setting:
   - Target group health check path: `/health`
   - Health check interval: 30s
   - Healthy threshold: 2
   - Unhealthy threshold: 3

### Load Balancer Health Checks

Configure ALB target group:
- **Path:** `/health`
- **Interval:** 30 seconds
- **Timeout:** 5 seconds
- **Healthy threshold:** 2
- **Unhealthy threshold:** 3
- **Success codes:** 200

## App Runner

App Runner provides a simpler deployment with managed scaling and load balancing.

1. Build and push to ECR:
   ```bash
   aws ecr create-repository --repository-name auth2  # if not exists
   docker build -t ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/auth2:latest .
   aws ecr get-login-password --region REGION | docker login --username AWS --password-stdin ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com
   docker push ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/auth2:latest
   ```

2. Edit `apprunner-service.json` (replace ACCOUNT_ID, REGION, image URI)

3. Create App Runner service:
   ```bash
   aws apprunner create-service --cli-input-json file://apprunner-service.json
   ```

4. Add environment variables via Console or:
   ```bash
   aws apprunner update-service --service-arn <arn> \
     --instance-configuration "InstanceRoleArn=..." \
     # Use Console for env vars or create custom role
   ```

App Runner health checks use `/health` by default (configured in `apprunner-service.json`).
