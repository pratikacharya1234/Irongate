# IronGate — AI Agent Security Platform v2.0

**Registry · Threat Detection · Behavioral Analytics · Global Ban Propagation · KYA Verification · Trust Network**

IronGate is a production-grade security platform for monitoring, verifying, and controlling AI agents across your infrastructure. It provides real-time threat detection, behavioral anomaly analysis, Know Your Agent (KYA) verification workflows, cross-platform ban propagation, and a decentralized trust network for sharing threat intelligence.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [API Reference](#api-reference)
5. [Core Modules](#core-modules)
6. [Database Schema](#database-schema)
7. [Security](#security)
8. [WebSocket Real-Time Feed](#websocket-real-time-feed)
9. [Deployment](#deployment)
10. [Testing](#testing)
11. [Contributing](#contributing)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    IronGate Platform                       │
├─────────────┬──────────────┬──────────────┬────────────────┤
│   REST API  │  WebSocket   │  Background  │  Trust Network  │
│  (Express)  │  Live Feed   │    Jobs      │  Peer Sync      │
├─────────────┴──────────────┴──────────────┴────────────────┤
│                     Service Layer                            │
│  Auth · Agents · Threats · Bans · KYA · Analytics · Network │
├────────────────────────────────────────────────────────────┤
│                   Data Layer (SQLite/WAL)                    │
│  agents · threats · bans · kya_submissions · detection_rules │
│  agent_activity · trust_peers · intel_broadcasts · audit_log │
└────────────────────────────────────────────────────────────┘
```

**Tech Stack:**
- **Runtime:** Node.js 18+
- **Framework:** Express.js 4
- **Database:** SQLite (better-sqlite3) with WAL mode
- **Auth:** JWT (access + refresh tokens) + bcrypt
- **Real-time:** WebSocket (ws)
- **Security:** Helmet, CORS, HPP, rate limiting, input validation (Joi)
- **Logging:** Winston (structured, file + console)
- **Container:** Docker + Docker Compose

---

## Quick Start

### Prerequisites
- Node.js >= 18
- npm >= 9

### Install & Run

```bash
# Setup (installs deps, runs migrations, seeds test data)
npm run setup

# Copy and configure environment
cp .env.example .env
# Edit .env — at minimum, set JWT_SECRET to a random 64-char string

# Start development server
npm run dev

# Server runs at http://localhost:4000
# API base: http://localhost:4000/api/v1
# WebSocket: ws://localhost:4000/ws
```

### Docker

```bash
# Set your JWT secret
export JWT_SECRET=$(openssl rand -hex 32)

# Build and run
docker-compose up -d

# View logs
docker-compose logs -f irongate
```

### Default Credentials (dev/test only)

| Email | Password | Role |
|---|---|---|
| admin@irongate.io | admin123!@# | admin |
| analyst@irongate.io | analyst123!@# | analyst |
| viewer@irongate.io | analyst123!@# | viewer |

**Change these immediately in production.**

---

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `PORT` | 4000 | HTTP server port |
| `JWT_SECRET` | — | **Required in production.** Min 32 chars. |
| `JWT_EXPIRES_IN` | 24h | Access token lifetime |
| `DB_PATH` | ./data/irongate.db | SQLite database path |
| `RATE_LIMIT_MAX` | 100 | Max requests per 15-min window |
| `CORS_ORIGIN` | http://localhost:3000 | Allowed CORS origins (comma-separated) |
| `LOG_LEVEL` | info | Winston log level |
| `THREAT_AUTO_BAN_SCORE` | 85 | Auto-ban threshold (threat confidence) |
| `BAN_WEBHOOK_URL` | — | Webhook URL for ban notifications |
| `REDIS_URL` | — | Optional Redis for caching/pub-sub |

---

## API Reference

All endpoints are prefixed with `/api/v1`. Authentication is via Bearer token in the Authorization header.

### Authentication

```
POST /auth/login          — Login (returns JWT)
POST /auth/register       — Register new user (admin only)
GET  /auth/me             — Get current user
POST /auth/refresh        — Refresh access token
```

### Dashboard

```
GET /dashboard            — Aggregated overview stats
GET /dashboard/audit      — Audit log (admin only)
```

### Agent Registry

```
GET    /agents            — List agents (paginated, filterable)
GET    /agents/:id        — Get agent details + recent threats + bans
POST   /agents            — Register new agent (admin/analyst)
PUT    /agents/:id        — Update agent (admin/analyst)
DELETE /agents/:id        — Delete agent (admin only)
POST   /agents/:id/verify — Verify agent (admin/analyst)
```

**Query Parameters:** `page`, `limit`, `sort`, `order`, `search`, `status`, `from`, `to`

### Threat Detection

```
GET   /threats            — List threats (paginated, filterable)
GET   /threats/stats      — Threat statistics
GET   /threats/:id        — Get threat details
POST  /threats            — Report new threat (admin/analyst)
PATCH /threats/:id/review — Review/mark false positive (admin/analyst)
```

**Query Parameters:** `severity`, `type`, `search`, `from`, `to`

### Ban Management

```
GET  /bans               — List bans (paginated)
GET  /bans/stats         — Ban statistics
POST /bans               — Create ban + propagate (admin/analyst, rate-limited)
POST /bans/:id/revoke    — Revoke ban (admin only)
```

### KYA (Know Your Agent)

```
GET   /kya               — List KYA submissions
GET   /kya/:id           — Get submission details
POST  /kya               — Submit KYA application
PATCH /kya/:id/review    — Approve or reject (admin/analyst)
```

### Behavioral Analytics

```
GET    /analytics/anomalies  — Agents with anomalous behavior
GET    /analytics/activity   — Activity timeline (by agent or global)
GET    /analytics/rules      — List detection rules
POST   /analytics/rules      — Create rule (admin/analyst)
PUT    /analytics/rules/:id  — Update rule (admin/analyst)
DELETE /analytics/rules/:id  — Delete rule (admin only)
```

### Trust Network

```
GET    /network/peers       — List trust network peers
POST   /network/peers       — Add peer (admin only)
DELETE /network/peers/:id   — Remove peer (admin only)
GET    /network/broadcasts  — Intel broadcasts log
GET    /network/stats       — Network statistics
```

### Health

```
GET /health              — Server health check (no auth)
```

---

## Core Modules

### 1. Agent Registry
Every AI agent/bot that interacts with your systems gets a unique identity record including a cryptographic fingerprint, organization info, trust score (0–100), purpose declaration, and rate limit tier.

### 2. Threat Detection Engine
Real-time analysis of agent behavior against configurable detection rules. Supports 13 threat types including prompt injection, data exfiltration, identity spoofing, privilege escalation, and swarm attacks. Auto-degrades trust scores for high-severity threats.

### 3. Global Ban Propagation
When an agent is banned, the ban is propagated to all connected trust network peers via webhooks. Each ban includes the agent's fingerprint, IP addresses, and behavioral signature for cross-platform blocking.

### 4. KYA (Know Your Agent) Verification
Structured verification workflow requiring organizations to declare their agent's purpose, expected data access scope, rate limits, and compliance certifications before receiving verified status.

### 5. Behavioral Analytics
Pattern-based anomaly detection with configurable rules: rate spikes, endpoint hopping, credential rotation, data volume anomalies, temporal patterns, and coordinated swarm detection.

### 6. Trust Network
Decentralized peer-to-peer network for sharing threat intelligence. Peers share fingerprints, ban records, threat signatures, and behavioral patterns in real-time.

### 7. Audit System
Immutable log of every administrative action: agent changes, ban operations, KYA reviews, rule modifications — with user attribution and IP tracking.

---

## Database Schema

The database uses SQLite with WAL mode for concurrent read performance. Key tables:

- **users** — Platform operators (admin, analyst, viewer roles)
- **agents** — AI agent registry with fingerprints and trust scores
- **agent_api_keys** — API key management per agent
- **threats** — Detected threat events
- **bans** — Ban records with propagation tracking
- **kya_submissions** — KYA verification workflow
- **detection_rules** — Behavioral analysis rules
- **agent_activity** — Request-level activity log
- **trust_peers** — Network peer connections
- **intel_broadcasts** — Shared threat intelligence
- **audit_log** — Immutable admin action log

All tables have appropriate indexes for query performance. See `src/db/migrate.js` for the full schema.

---

## Security

### Authentication & Authorization
- JWT access tokens (configurable expiry, default 24h)
- Refresh tokens (7d) for seamless token rotation
- Role-based access: `admin` (full), `analyst` (read + write), `viewer` (read only)
- bcrypt password hashing (configurable rounds, default 12)

### Request Security
- **Helmet** — Security headers (CSP, HSTS, X-Frame-Options, etc.)
- **CORS** — Configurable allowed origins
- **HPP** — HTTP Parameter Pollution protection
- **Rate Limiting** — Global (100/15min), Auth (20/15min), Ban operations (10/min)
- **Input Validation** — Joi schemas on all inputs with strict type checking
- **Request IDs** — Unique ID per request for tracing

### Data Security
- Sensitive data never logged (passwords, tokens, full payloads)
- SQL injection prevented by parameterized queries (better-sqlite3)
- Request payloads size-limited (1MB)
- Audit trail for all mutations

---

## WebSocket Real-Time Feed

Connect to `ws://HOST:PORT/ws?token=JWT_TOKEN` for real-time events.

### Channels
- `threats` — New threat events
- `bans` — New ban events
- `dashboard` — Stats updates

### Message Format

```json
{
  "type": "event",
  "channel": "threats",
  "data": { "event": "new_threat", "threat": { ... } },
  "timestamp": 1710000000000
}
```

### Commands

```json
{"type": "subscribe", "channel": "bans"}
{"type": "unsubscribe", "channel": "dashboard"}
{"type": "ping"}
```

---

## Deployment

### Production Checklist

1. Set `NODE_ENV=production`
2. Generate a strong `JWT_SECRET` (min 64 chars): `openssl rand -hex 32`
3. Set `CORS_ORIGIN` to your frontend domain
4. Configure `BAN_WEBHOOK_URL` for ban propagation
5. Set up log rotation for `./logs/`
6. Place behind a reverse proxy (nginx, Caddy) with TLS
7. Set up monitoring on `/api/v1/health`
8. Review and adjust rate limits for your traffic

### Nginx Reverse Proxy Example

```nginx
server {
    listen 443 ssl http2;
    server_name shield.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /api/ {
        proxy_pass http://127.0.0.1:4000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:4000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location / {
        root /path/to/irongate/frontend/build;
        try_files $uri /index.html;
    }
}
```

---

## Testing

```bash
# Run all tests
npm test

# Unit tests only
npm run test:unit

# Integration tests
npm run test:integration

# With coverage report
npm test -- --coverage
```

Tests use Jest + Supertest and a separate test database.

---

## Project Structure

```
irongate/
├── src/
│   ├── server.js              # Entry point
│   ├── config/                # Config loader
│   ├── db/
│   │   ├── connection.js      # SQLite connection
│   │   ├── migrate.js         # Schema migrations
│   │   ├── seed.js            # Test data seeder
│   │   └── reset.js           # Reset database
│   ├── api/
│   │   ├── routes/            # Express routes
│   │   ├── controllers/       # Request handlers
│   │   │   ├── authController.js
│   │   │   ├── agentsController.js
│   │   │   ├── threatsController.js
│   │   │   ├── bansController.js
│   │   │   ├── kyaController.js
│   │   │   ├── analyticsController.js
│   │   │   ├── networkController.js
│   │   │   └── dashboardController.js
│   │   ├── middleware/
│   │   │   ├── auth.js        # JWT + RBAC
│   │   │   ├── security.js    # Helmet, CORS, rate limit
│   │   │   ├── errorHandler.js
│   │   │   └── audit.js       # Audit logging
│   │   ├── validators/        # Joi schemas
│   │   └── services/
│   │       └── websocket.js   # Real-time feed
│   └── utils/
│       └── logger.js          # Winston logger
├── tests/
│   ├── unit/
│   └── integration/
│       └── api.test.js
├── docs/
│   └── API.md
├── frontend/                  # React frontend (separate)
├── Dockerfile
├── docker-compose.yml
├── package.json
├── .env.example
└── README.md
```

---

## API Response Format

All responses follow a consistent format:

### Success
```json
{
  "data": { ... },
  "meta": { "total": 100, "page": 1, "limit": 25, "pages": 4 }
}
```

### Error
```json
{
  "error": "VALIDATION_ERROR",
  "message": "Invalid input",
  "details": [{ "field": "email", "message": "must be a valid email" }],
  "requestId": "abc-123"
}
```

---

## License

MIT

---

Built for securing the agentic AI era.
