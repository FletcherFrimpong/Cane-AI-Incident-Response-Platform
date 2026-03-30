# Cane AI - Incident Response Platform

An AI-powered security incident response platform that ingests Microsoft security logs, triages them using AI, auto-responds to known threats via NIST 800-61 playbooks, and guides analysts through human-in-the-loop remediation for incidents requiring manual intervention.

## Key Features

- **Fully Automated TDIR Pipeline** - End-to-end automation from log ingestion to containment. Logs are ingested, normalized, correlated into incidents, enriched with threat intelligence, triaged by AI, and contained — all without human intervention. Analysts only engage when the AI flags incidents for review.
- **Auto-Enrichment** - Before AI analysis, IOCs (IPs, file hashes, domains, URLs) are extracted from log events and queried against VirusTotal and AbuseIPDB. Threat intel scores are fed into the LLM prompt for more accurate triage decisions.
- **AI-Powered Triage** - Supports Claude, OpenAI, and Azure OpenAI via system-level API key or per-user BYOK. The AI classifies severity, identifies attack types, maps to MITRE ATT&CK, extracts IOCs, assesses kill chain phase, and recommends response actions with auto-execute flags.
- **Auto-Containment** - AI-recommended actions with confidence >= 95% auto-execute via integrations (block IP, isolate host, disable account). Below-threshold actions queue in the Action Queue for analyst approval with full context.
- **Real-Time Log Ingestion** - Ingest security logs via webhooks or batch file upload. Supports all 14 Azure Sentinel ASIM log types with automatic normalization.
- **Event Correlation** - Automatically groups related events by correlation ID, detects attack patterns (ransomware, phishing, exfiltration, etc.), and creates incidents.
- **NIST 800-61 Playbooks** - 7 pre-built incident response playbooks (Ransomware, Phishing, Data Exfiltration, DDoS, Unauthorized Access, Malware, Insider Threat) with 59 guided steps.
- **SOC Analyst Queue** - Incidents sorted by severity and status priority. Critical/awaiting-analyst incidents surface first. Incident Detail page serves as the full response hub: AI analysis, MITRE mapping, IOCs, action approval, timeline with analyst notes.
- **Real Platform Integrations** - Microsoft Graph, Sentinel, Defender for Endpoint, VirusTotal, AbuseIPDB. All with OAuth2/API key auth, encrypted credential storage, connection testing, and health monitoring.
- **Role-Based Access** - Four roles (Tier 1 Analyst, Tier 2 Analyst, Manager, Admin) with granular permissions.

## Architecture

```
                                    +------------------+
                                    |    Frontend      |
                                    |  React + TS      |
                                    |  Tailwind CSS    |
                                    +--------+---------+
                                             |
                                        WebSocket + REST
                                             |
+------------------+            +------------+-------------+
|  Microsoft       |  Webhook   |                          |
|  Sentinel        +----------->+     FastAPI Backend      |
|  / Defender      |            |                          |
+------------------+            +--+-----+-----+-----+----+
                                   |     |     |     |
                          +--------+  +--+--+  |  +--+--------+
                          |           |     |  |  |           |
                    +-----+----+ +---+---+ | +--+------+ +---+--------+
                    |  Log     | | AI    | | | Action  | | Integration|
                    |Normalizer| |Triage | | | Service | | Service    |
                    |14 ASIM   | | BYOK  | | |Approval | | Encrypted  |
                    | types    | |Claude | | |Workflow | | Credentials|
                    +-----+----+ |OpenAI | | +---+-----+ +---+--------+
                          |      |Azure  | |     |            |
                          |      +---+---+ |     |     +------+------+
                    +-----+----+     |     |     |     |  Microsoft  |
                    |Correlation|    |  +--+--+  |     |  Graph API  |
                    |  Engine   |    |  |Celery|  |     |  Sentinel   |
                    |CorrelID + |    |  |Worker|  |     |  Defender   |
                    |Time Window|    |  +--+---+  |     |  VirusTotal |
                    +-----+----+    |     |       |     |  AbuseIPDB  |
                          |         |     |       |     +-------------+
                    +-----+---------+-----+-------+----+
                    |          PostgreSQL               |
                    |  incidents | log_events | users   |
                    |  playbooks | ai_analyses| actions |
                    |  timeline  | integrations| audit  |
                    +------------------+----------------+
                                       |
                                 +-----+-----+
                                 |   Redis    |
                                 | Broker +   |
                                 | Cache      |
                                 +-----------+
```

### Automated TDIR Pipeline

The platform implements a fully automated Threat Detection, Investigation, and Response (TDIR) pipeline following NIST 800-61 and industry best practices. Every step runs without human intervention — analysts only get involved when the AI flags an incident for review.

```
1. DETECTION & INGESTION
   Sentinel Webhook / File Upload / Batch API
           |
           v
   Log Normalizer (14 ASIM schema types)
           |
           v
   Correlation Engine (group by CorrelationId + time window)
           |
           +---> Existing incident? Link event to it
           +---> New correlation group? Create incident
           |
           v
   Store in PostgreSQL (log_events table, JSONB raw data)

2. AUTO-ENRICHMENT (Celery background task)
   Incident created
           |
           v
   Extract IOCs from log events:
   - Public IPs (filter out RFC-1918 private ranges)
   - File hashes (SHA256/SHA1/MD5 from raw data)
   - Domains and URLs
           |
           v
   Query Threat Intelligence (if configured):
   - VirusTotal: IP/hash/domain/URL reputation, malicious counts
   - AbuseIPDB: IP abuse confidence score, report count
           |
           v
   Enrichment results fed into AI prompt
   (Graceful skip if integrations not configured)

3. AI TRIAGE
   Enriched events + incident context
           |
           v
   System LLM API key (CANE_AUTO_TRIAGE_API_KEY)
           |
           v
   Claude / OpenAI / Azure OpenAI (temperature: 0.1)
           |
           v
   Structured JSON response:
   - Severity classification (critical/high/medium/low/info)
   - Attack type identification
   - MITRE ATT&CK mapping (tactics + technique IDs)
   - Kill chain phase
   - Confidence score (0.0 - 1.0)
   - IOCs extracted (IPs, domains, hashes, emails)
   - Recommended actions with priority and auto-execute flag
   - Playbook suggestion
   - Human review determination
           |
           v
   Update incident + Store AI analysis + Match playbook

4. AUTO-CONTAINMENT
   For each AI-recommended action:
           |
           v
   Confidence >= 0.95 AND can_auto_execute?
           |
          YES --> Execute immediately via integration:
           |      - Block IP (Microsoft Defender)
           |      - Isolate host (Microsoft Defender)
           |      - Disable account (Microsoft Graph)
           |      - Revoke sessions (Microsoft Graph)
           |      - Block URL/hash (Microsoft Defender)
           |
          NO --> Create pending action for analyst approval
           |
           v
   All actions logged in audit trail with full context

5. ANALYST REVIEW (only when needed)
   Incident Detail page shows:
   - AI analysis summary with confidence
   - MITRE ATT&CK mapping
   - Extracted IOCs with threat intel scores
   - Pending actions with Approve / Reject buttons
           |
           v
   On Approve: Execute via integration APIs
   On Reject: Log reason, continue to next action

6. PLAYBOOK EXECUTION
   Playbook attached to incident (AI-recommended or manual)
           |
           v
   Step-by-step execution:
   - AUTOMATED steps -> Execute via integrations (may require approval)
   - HUMAN_DECISION steps -> Present options to analyst
   - HUMAN_ACTION steps -> Analyst performs and marks complete
   - INFO steps -> Display guidance (NIST 800-61 references)
           |
           v
   Advance through NIST phases:
   Detection & Analysis -> Containment -> Eradication -> Recovery -> Post-Incident
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11+, FastAPI, SQLAlchemy (async), Celery |
| Frontend | React 18, TypeScript, Tailwind CSS, Zustand, React Query |
| Database | PostgreSQL 16 |
| Cache/Broker | Redis 7 |
| AI Providers | Anthropic Claude, OpenAI, Azure OpenAI (BYOK) |
| Integrations | Microsoft Graph, Sentinel, Defender, VirusTotal, AbuseIPDB |
| Deployment | Docker Compose (dev), Azure Container Apps (prod) |

## Project Structure

```
my-app/
├── docker-compose.yml          # PostgreSQL, Redis, Backend, Celery, Frontend
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI application
│   │   ├── config.py           # Pydantic Settings (env-based)
│   │   ├── database.py         # Async SQLAlchemy engine
│   │   ├── models/             # 11 SQLAlchemy ORM models
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── api/                # FastAPI route modules (62 endpoints)
│   │   │   ├── auth.py         # Register, login, refresh
│   │   │   ├── users.py        # Profile, API key management
│   │   │   ├── incidents.py    # CRUD, assign, escalate, close, timeline
│   │   │   ├── logs.py         # Ingest, batch, upload, query
│   │   │   ├── playbooks.py    # CRUD, step management, execute
│   │   │   ├── triage.py       # AI analyze, correlate, recommendations
│   │   │   ├── actions.py      # Execute, approve, reject, history
│   │   │   ├── dashboard.py    # Overview, threats, geo, timeline
│   │   │   └── integrations.py # CRUD, test connection, health
│   │   ├── services/           # Business logic layer
│   │   │   ├── log_normalizer.py   # 14 ASIM log type normalizers
│   │   │   ├── correlation.py      # Event correlation engine
│   │   │   ├── log_ingestion.py    # Ingestion orchestration
│   │   │   ├── enrichment_service.py  # IOC extraction + threat intel queries
│   │   │   ├── triage_service.py   # AI triage + auto-containment orchestration
│   │   │   ├── playbook_service.py # Playbook execution engine
│   │   │   ├── action_service.py   # Auto-response + approval workflow
│   │   │   ├── integration_service.py # Credential encryption + health
│   │   │   ├── auth_service.py     # JWT + password hashing
│   │   │   └── encryption_service.py  # AES-256-GCM encryption
│   │   ├── ai/                 # LLM integration (BYOK)
│   │   │   ├── provider_base.py    # LLMProvider protocol
│   │   │   ├── claude_provider.py  # Anthropic Claude
│   │   │   ├── openai_provider.py  # OpenAI
│   │   │   ├── azure_openai_provider.py # Azure OpenAI
│   │   │   ├── provider_factory.py # Factory (resolves user or system API key)
│   │   │   └── prompts/           # Structured prompt templates
│   │   ├── integrations/       # Platform connectors
│   │   │   ├── base_client.py      # ABC + OAuth2 mixin
│   │   │   ├── microsoft_graph.py  # Disable user, revoke sessions, etc.
│   │   │   ├── microsoft_sentinel.py # KQL queries, incidents, watchlists
│   │   │   ├── microsoft_defender.py # Isolate, block, AV scan
│   │   │   ├── threat_intel.py     # VirusTotal + AbuseIPDB
│   │   │   └── registry.py        # Integration registry
│   │   ├── data/
│   │   │   └── seed_playbooks.py   # 7 NIST 800-61 playbooks (59 steps)
│   │   └── workers/
│   │       ├── celery_app.py       # Celery config + beat schedule
│   │       └── triage_tasks.py     # Auto-triage background tasks
│   └── alembic/                # Database migrations
├── frontend/
│   ├── src/
│   │   ├── App.tsx             # Routes + auth guard
│   │   ├── api/                # Axios API client layer
│   │   ├── store/              # Zustand state management
│   │   ├── pages/              # Dashboard, Incidents, Action Queue, Playbooks, Logs, Settings
│   │   ├── components/         # Layout (AppShell, Sidebar)
│   │   ├── types/              # TypeScript interfaces
│   │   └── utils/              # Constants, formatters
│   └── package.json
└── synthetic_logs/             # 14 ASIM log files + 4 attack scenario files
```

## Pre-Built Playbooks

| Playbook | Attack Types | Steps | Key Auto-Actions |
|----------|-------------|-------|-----------------|
| Ransomware Response | ransomware | 11 | Isolate host, block C2 IPs, full AV scan |
| Phishing Response | phishing | 9 | Block URLs, reset credentials, revoke sessions |
| Data Exfiltration Response | data_exfiltration | 9 | Disable account, block destination IPs |
| DDoS Response | ddos | 6 | Block source IPs |
| Unauthorized Access Response | unauthorized_access, brute_force | 8 | Disable accounts, revoke sessions, block IPs |
| Malware Infection Response | malware | 8 | Isolate host, block file hash, block C2, AV scan |
| Insider Threat Response | insider_threat | 8 | Disable account (with HR/Legal approval) |

All playbooks follow NIST SP 800-61 phases: Detection & Analysis, Containment, Eradication, Recovery, Post-Incident Activity.

## Supported Log Types (ASIM Schema)

| Log Type | Source | Key Fields Extracted |
|----------|--------|---------------------|
| SecurityAlert | Microsoft Defender | Severity, entities, tactics, alert name |
| SecurityEvent | Windows | Event ID, account, process, command line |
| SignInLogs | Azure AD | User, IP, location, risk level |
| CommonSecurityLog | Palo Alto, Cisco, Fortinet, Check Point | Source/dest IP, device action, threat |
| EmailEvents | Defender for Office 365 | Sender, recipient, subject, threat type |
| EmailAttachmentInfo | Defender for Office 365 | Filename, hash, threat |
| EmailUrlInfo | Defender for Office 365 | URL, domain, threat |
| DNSEvents | DNS Server | Query name, client IP, threat indicator |
| AppServiceHTTPLogs | Azure App Service | Method, URI, status, client IP |
| AuditLogs | Azure AD | Operation, actor, target |
| OfficeActivity | Microsoft 365 | Operation, workload, user |
| AWSCloudTrail | AWS | Event name, source, user identity |
| Event | Windows | Event ID, source, message |
| Heartbeat | Azure Monitor | Computer, OS, environment |

## Platform Integrations

| Platform | Auth | Capabilities |
|----------|------|-------------|
| Microsoft Graph | OAuth2 Client Credentials | Disable/enable user, revoke sessions, force password reset, read security alerts, read risky users |
| Microsoft Sentinel | OAuth2 Client Credentials | Run KQL queries, list/update incidents, create watchlists |
| Microsoft Defender for Endpoint | OAuth2 Client Credentials | Isolate/release machine, AV scan, block IP/URL/hash, collect investigation package |
| VirusTotal | API Key | File hash, IP, domain, URL reputation lookup |
| AbuseIPDB | API Key | IP reputation check, report malicious IPs |

All credentials are AES-256-GCM encrypted at rest. Each integration supports dry-run mode and automated health checks.

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Node.js 20+ (for local frontend development)
- Python 3.11+ (for local backend development)

### Quick Start with Docker

```bash
cd my-app
docker-compose up --build
```

On first run, create the database tables:

```bash
docker-compose exec backend python -c "
import asyncio
from app.database import engine
from app.models.base import Base
import app.models
async def init():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print('Tables created')
asyncio.run(init())
"
```

Register your first user:

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "changeme", "full_name": "Admin", "role": "admin"}'
```

Services will be available at:
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs
- **API Docs (ReDoc)**: http://localhost:8000/redoc

### Local Development

**Backend:**
```bash
cd my-app/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start PostgreSQL and Redis (via Docker or locally)
docker-compose up postgres redis -d

# Run migrations
alembic upgrade head

# Start the server
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd my-app/frontend
npm install
npm run dev
```

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Required
CANE_DATABASE_URL=postgresql+asyncpg://cane:cane_secret@localhost:5432/cane_db
CANE_REDIS_URL=redis://localhost:6379/0
CANE_JWT_SECRET_KEY=your-secret-key-here
CANE_ENCRYPTION_MASTER_KEY=your-encryption-key-here

# Automated AI Triage (set API key to enable)
CANE_AUTO_TRIAGE_ENABLED=true
CANE_AUTO_TRIAGE_PROVIDER=claude          # claude, openai, or azure_openai
CANE_AUTO_TRIAGE_API_KEY=sk-ant-...       # System-level LLM API key
CANE_AUTO_TRIAGE_MODEL=                   # Optional model override

# Auto-enrichment (query threat intel before AI triage)
CANE_AUTO_ENRICHMENT_ENABLED=true
CANE_AUTO_ENRICHMENT_MAX_IOCS=4          # Max IOCs per type to query (rate limit control)

# Auto-containment threshold
CANE_AUTO_RESPONSE_CONFIDENCE_THRESHOLD=0.95  # Actions above this auto-execute
```

When `CANE_AUTO_TRIAGE_API_KEY` is set, the full TDIR pipeline runs automatically:
1. Incident created from correlated logs
2. IOCs extracted and queried against VirusTotal/AbuseIPDB (if configured in Settings > Integrations)
3. AI triages the incident with enriched data
4. High-confidence actions auto-execute via integrations; others queue for analyst approval

## API Overview

| Endpoint Group | Routes | Description |
|---------------|--------|-------------|
| `/api/v1/auth` | 3 | Register, login, refresh token |
| `/api/v1/users` | 6 | Profile, roles, API key management |
| `/api/v1/logs` | 5 | Ingest, batch, upload, query, schemas |
| `/api/v1/incidents` | 9 | CRUD, assign, escalate, close, timeline, evidence, notes |
| `/api/v1/triage` | 4 | AI analyze, results, recommendations, correlate |
| `/api/v1/playbooks` | 8 | CRUD, steps, execute |
| `/api/v1/actions` | 4 | Execute, approve, reject, history |
| `/api/v1/dashboard` | 4 | Overview, threats, geo, timeline |
| `/api/v1/integrations` | 8 | CRUD, platforms, test, health |

## Role-Based Access Control

| Action | Tier 1 | Tier 2 | Manager | Admin |
|--------|--------|--------|---------|-------|
| View incidents & logs | Yes | Yes | Yes | Yes |
| Triage incidents | Yes | Yes | Yes | Yes |
| Approve/execute actions | No | Yes | Yes | Yes |
| Manage playbooks | No | No | Yes | Yes |
| Manage integrations | No | No | No | Yes |
| Manage users | No | No | No | Yes |

## Security

- JWT authentication with short-lived access tokens (15 min) and rotatable refresh tokens (7 days)
- AES-256-GCM encryption for all stored API keys and integration credentials
- Role-based access control on all endpoints
- Request logging middleware with audit trail
- CORS configuration for frontend origin
- Input validation via Pydantic on all API endpoints

## License

MIT
