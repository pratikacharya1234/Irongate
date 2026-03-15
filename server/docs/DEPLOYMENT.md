# IronGate — Deployment Guide

## Prerequisites

- Docker & Docker Compose v2.20+
- Domain name with DNS configured
- SSL certificate (Let's Encrypt recommended)

## Production Deployment

### 1. Server Setup

```bash
# Ubuntu 24.04 recommended
sudo apt update && sudo apt upgrade -y
sudo apt install docker.io docker-compose-v2 -y
sudo usermod -aG docker $USER
```

### 2. Clone & Configure

```bash
cp .env.example .env
```

**Edit `.env` — critical fields to change:**
```bash
SECRET_KEY=<random 64-char string>
JWT_SECRET_KEY=<random 64-char string>
DB_PASSWORD=<strong database password>
WEBHOOK_SECRET=<random 32-char string>
TRUST_NETWORK_SHARED_SECRET=<random 32-char string>
TRUST_NETWORK_NODE_ID=<your unique node identifier>
ALLOWED_ORIGINS=https://your-domain.com
```

Generate secrets:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 3. SSL Certificates

```bash
mkdir -p nginx/ssl

# Option A: Let's Encrypt (recommended)
sudo certbot certonly --standalone -d your-domain.com
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/cert.pem
cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/key.pem

# Option B: Self-signed (development only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem -out nginx/ssl/cert.pem \
  -subj "/CN=localhost"
```

### 4. Launch

```bash
docker compose up -d

# Run database migrations
docker compose exec api alembic upgrade head

# Create admin user
docker compose exec api python -c "
import asyncio
from app.core.database import async_session_factory
from app.core.security import hash_password
from app.models.models import User, UserRole

async def create_admin():
    async with async_session_factory() as db:
        user = User(
            email='admin@your-domain.com',
            username='admin',
            hashed_password=hash_password('YourSecurePassword123!@#'),
            full_name='System Admin',
            role=UserRole.SUPERADMIN,
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        await db.commit()
        print('Admin created')

asyncio.run(create_admin())
"
```

### 5. Verify

```bash
# Health check
curl https://your-domain.com/api/v1/health

# Expected:
# {"status":"healthy","version":"2.0.0","database":"healthy","redis":"healthy",...}
```

## Scaling

### Horizontal API scaling
```bash
# Scale API workers
docker compose up -d --scale api=4
```

### Celery worker scaling
```bash
# Add more workers for ban propagation
docker compose up -d --scale worker=8
```

### Database read replicas
For high-read workloads (ban checks), configure PostgreSQL streaming replication and point read-only queries to replicas.

## Monitoring

### Log aggregation
All services output JSON-formatted logs. Ship to your SIEM:
```bash
# Tail API logs
docker compose logs -f api

# Export to file
docker compose logs api > /var/log/irongate/api.log
```

### Prometheus metrics
Add to docker-compose.yml:
```yaml
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
```

### Alerting
Configure Slack/PagerDuty webhooks in `.env`:
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
PAGERDUTY_API_KEY=your-pagerduty-key
```

## Backup

### Database
```bash
# Daily backup
docker compose exec db pg_dump -U irongate irongate | gzip > backup-$(date +%Y%m%d).sql.gz

# Restore
gunzip -c backup-20260312.sql.gz | docker compose exec -T db psql -U irongate irongate
```

### Redis
Redis data is ephemeral (cache + pub/sub). No backup needed for most deployments.

## Security Hardening

1. **Firewall:** Only expose ports 80/443. Block direct access to 5432, 6379, 8000
2. **Network:** Use Docker network isolation (already configured)
3. **Secrets:** Never commit `.env`. Use Docker secrets or Vault in production
4. **Updates:** Run `docker compose pull && docker compose up -d` regularly
5. **Audit:** Monitor `/var/log/irongate/audit.log` for suspicious admin actions
6. **Rotation:** Rotate JWT secrets and API keys quarterly
