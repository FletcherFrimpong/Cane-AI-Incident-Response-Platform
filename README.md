# Cane AI - Incident Response Platform

An AI-powered security incident response platform that ingests Microsoft security logs, triages them using AI, auto-responds to known threats via NIST 800-61 playbooks, and guides analysts through human-in-the-loop remediation for incidents requiring manual intervention.

## Key Features

- **AI-Powered Triage** - BYOK (Bring Your Own Key) model supporting Claude, OpenAI, and Azure OpenAI. The AI classifies severity, identifies attack types, maps to MITRE ATT&CK, and recommends response actions.
- **Real-Time Log Ingestion** - Ingest security logs via real-time webhooks or batch file upload. Supports all 14 Azure Sentinel ASIM log types with automatic normalization.
- **Event Correlation** - Automatically groups related events by correlation ID, detects attack patterns, and creates incidents with full kill-chain reconstruction.
- **NIST 800-61 Playbooks** - 7 pre-built incident response playbooks (Ransomware, Phishing, Data Exfiltration, DDoS, Unauthorized Access, Malware, Insider Threat) with 59 guided steps. Create custom playbooks via the UI.
- **Auto-Response with Approval Workflow** - Automated actions (block IP, disable account, quarantine email, isolate host) execute via real Microsoft APIs when AI confidence is high. Actions below threshold are routed to analysts for approval.
- **Human-in-the-Loop** - Analysts receive AI-recommended actions with reasoning. They can approve, modify, or reject. Step-by-step playbook guidance walks them through remediation.
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

### Data Flow

```
1. LOG INGESTION
   Sentinel Webhook / File Upload
           |
           v
   API /logs/ingest or /logs/upload
           |
           v
   Log Normalizer (14 ASIM schema types)
           |
           v
   Correlation Engine (group by CorrelationId)
           |
           +---> Existing incident? Link event to it
           +---> New correlation group? Create incident
           |
           v
   Store in PostgreSQL (log_events table, JSONB raw data)

2. AI TRIAGE
   Incident created
           |
           v
   Triage Service -> Provider Factory -> User's LLM API Key (decrypted)
           |
           v
   Claude / OpenAI / Azure OpenAI
           |
           v
   Structured JSON response:
   - Severity classification
   - Attack type identification
   - MITRE ATT&CK mapping
   - Confidence score (0.0 - 1.0)
   - Recommended actions
   - Playbook suggestion
           |
           v
   Update incident + Create AI analysis record

3. AUTO-RESPONSE / HUMAN-IN-THE-LOOP
   AI recommends action (e.g., block_ip, confidence: 0.87)
           |
           v
   Confidence >= 0.95? --YES--> Auto-execute via integration
           |
           NO
           |
           v
   Create pending action -> WebSocket notification to analysts
           |
           v
   Analyst reviews in Triage Queue:
   - Sees AI reasoning and evidence
   - Approves / Modifies / Rejects
           |
           v
   On Approve: Execute via Microsoft Defender / Graph API
   On Reject: Log reason, continue playbook

4. PLAYBOOK EXECUTION
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
│   │   │   ├── triage_service.py   # AI triage orchestration
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
│   │   │   ├── provider_factory.py # Factory (resolves user's API key)
│   │   │   └── prompts/           # Jinja2 prompt templates
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
│   │       └── celery_app.py       # Celery config + beat schedule
│   └── alembic/                # Database migrations
├── frontend/
│   ├── src/
│   │   ├── App.tsx             # Routes + auth guard
│   │   ├── api/                # Axios API client layer
│   │   ├── store/              # Zustand state management
│   │   ├── pages/              # Dashboard, Incidents, Triage, Playbooks, Logs, Settings
│   │   ├── components/         # Layout (AppShell, Sidebar)
│   │   ├── types/              # TypeScript interfaces
│   │   └── utils/              # Constants, formatters
│   └── package.json
├── synthetic_logs/             # 14 ASIM log files (30MB)
└── enhanced_synthetic_logs/    # 4 attack scenario files
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
docker-compose up
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
CANE_DATABASE_URL=postgresql+asyncpg://cane:cane_secret@localhost:5432/cane_db
CANE_REDIS_URL=redis://localhost:6379/0
CANE_JWT_SECRET_KEY=your-secret-key-here
CANE_ENCRYPTION_MASTER_KEY=your-encryption-key-here
```

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
