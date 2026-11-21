# Cane AI - Incident Response Platform

Cane AI is an incident response platform built around a ticket queue. Security logs come in, related events are grouped into incidents, an AI model triages each one and proposes containment, and analysts work the queue: approve or reject the proposed actions, follow a NIST 800-61 playbook, and close the incident with the evidence attached.

![Dashboard: updates feed, open-incident counts and the incidents that need attention](docs/screenshots/dashboard.jpg)

## Screenshots

**Incident queue.** Views with live counts on the left; incidents grouped by severity, with status, attack type and assignee.

![Incident queue](docs/screenshots/incidents.jpg)

**Incident page.** Properties and entities on the left, the conversation and internal notes in the middle, AI analysis, threat intelligence and response actions awaiting approval on the right.

![Incident page](docs/screenshots/incident-detail.jpg)

**Action queue.** Every containment action the AI or a playbook proposed, waiting for a tier 2 analyst or above.

![Action queue](docs/screenshots/action-queue.jpg)

**Playbooks.** Seven built-in NIST 800-61 playbooks, shown step by step with the automated action each step proposes.

![Playbooks](docs/screenshots/playbooks.jpg)

**Logs.** Every ingested event, filterable by severity and log type, linked to the incident it belongs to.

![Logs](docs/screenshots/logs.jpg)

**Integrations.** 27 connectors in five groups. New ones start in dry-run.

![Integrations](docs/screenshots/integrations.jpg)

The screenshots use the sample scenarios in `enhanced_synthetic_logs/`. The AI analysis shown comes from the built-in rule-based stand-in (`mock` provider), which is labelled as such in the UI; with an LLM key configured, a real model writes it.

## Key Features

- **Ticket-queue workspace** - The UI works like a help desk: views with live counts (Needs your attention, Assigned to you, Unassigned…), a dense incident queue grouped by severity, and an incident page with properties on the left, the conversation in the middle and AI analysis plus response actions on the right.
- **Automated TDIR pipeline** - Logs are ingested, normalized, correlated into incidents, enriched with threat intelligence and triaged by AI. Analysts are pulled in when the AI asks for review or proposes an action that needs a person.
- **Incidents only for what matters** - A correlated group opens an incident when its worst event reaches medium severity, a security product raised an alert, or a known attack pattern is recognised. Routine informational events stay as searchable logs and are pulled into the incident if the group escalates later.
- **Auto-Enrichment** - Before AI analysis, IOCs (IPs, file hashes, domains, URLs) are extracted from log events and queried against VirusTotal and AbuseIPDB when those integrations are configured.
- **AI-Powered Triage** - Claude, OpenAI or Azure OpenAI, via a system-level key or a per-user key (BYOK). The model classifies severity, identifies the attack type, maps to MITRE ATT&CK, extracts IOCs and recommends response actions.
- **Guarded containment** - The model only ever suggests. A rule layer (`app/services/triage_guard.py`) decides what happens to each suggestion: see [How auto-containment is gated](#how-auto-containment-is-gated).
- **Real-Time Log Ingestion** - Webhook, batch API or file upload. Supports all 14 Azure Sentinel ASIM log types with automatic normalization. Machine senders authenticate with an ingest API key.
- **NIST 800-61 Playbooks** - 7 built-in playbooks (59 steps) loaded automatically at startup, attached by AI triage or by hand, and worked step by step from the incident page. When the playbook reaches an automated step (isolate hosts, block C2 addresses), it proposes that action for each matching host, address or account in the incident's evidence, and moves on by itself once they have run.
- **Live updates** - Open pages refresh the moment an incident or the action queue changes (server-sent events over Redis), with slow polling as a fallback.
- **Notifications, paging and tickets** - Serious incidents and approval requests go to Slack, Teams, PagerDuty, Opsgenie or any webhook; Jira and ServiceNow tickets are opened, commented and closed in step with the incident.
- **27 integrations** - Response tools, threat intelligence, identity and device context, chat and paging, ticketing, and log sources. Encrypted credential storage, connection testing, scheduled health checks. New integrations start in dry-run mode.
- **Role-Based Access** - Four roles (Tier 1 Analyst, Tier 2 Analyst, Manager, Admin). Accounts are created by an admin.

## Architecture

![Cane AI architecture: log sources and analysts at the top, the six-step backend pipeline in the middle, PostgreSQL, Redis and Celery workers beneath it, and the outside tools reached through connectors at the bottom](docs/architecture.svg)

How to read it:

- **Top.** Events arrive by webhook, upload or batch, or are pulled from Splunk, Elastic and GuardDuty. Analysts use the browser app, which talks to the API and listens on a live update stream.
- **Middle.** One pipeline turns a raw event into a handled incident: ingest, correlate, enrich, AI triage, guard, act. The guard (step 5) is the safety boundary: nothing the model says reaches a real system without passing it.
- **Beneath.** PostgreSQL holds the data. Redis carries background jobs and live updates. Celery workers do the slow work: triage, notifications, ticket sync, polling sources, health checks.
- **Bottom.** Everything outside the platform is reached through a connector, and every new connector starts in dry-run.

### Automated TDIR Pipeline

Threat detection, investigation and response (TDIR), following NIST SP 800-61. Everything up to and including triage runs without a person. Containment is automatic only for a short allow-list of low-risk blocks; everything else waits for an analyst.

![Pipeline: five automatic stages ending in the guard, which sends each recommended action to the approval queue, to automatic execution, or drops it; an analyst then decides, connected tools act, the playbook moves on and the incident is closed](docs/pipeline.svg)

| Stage | What happens | Where a person comes in |
|-------|--------------|-------------------------|
| **1. Ingest** | Events arrive by Sentinel webhook, file upload or batch API, or are pulled every minute from Splunk, Elastic and GuardDuty. Each of the 14 log types is normalised into one event shape. A malformed event is rejected on its own; the rest of the batch still goes in. | Nobody |
| **2. Correlate** | Events sharing a correlation ID are grouped. A group becomes an incident when its worst event reaches medium severity, a security product raised an alert, or a known attack pattern is recognised. Quieter events stay as logs and are pulled in if the group escalates later. | Nobody |
| **3. Enrich** | IPs, domains, URLs and file hashes are checked against every connected threat-intelligence source, and the accounts and hosts involved are looked up in the directory and endpoint tools. Results are stored on the incident. Skipped quietly when nothing is connected. | Nobody |
| **4. AI triage** | The model receives the evidence and the enrichment and returns severity, attack type, MITRE ATT&CK mapping, kill-chain phase, confidence, recommended actions and whether a person should look. A matching playbook is attached. | An analyst can re-run triage from the incident page |
| **5. Guard** | The reply is validated; a malformed one is recorded as a failed triage and the incident goes to an analyst. Each recommended action is then sent to one of three outcomes (see the diagram and [How auto-containment is gated](#how-auto-containment-is-gated)). | Nobody. This is what stands between the model and real systems |
| **6. Act** | Queued actions wait on the incident page and in the action queue. An approved action goes to every connected tool that supports it, and each tool's result is recorded. | A tier 2 analyst or above approves or rejects, in the app or from Slack |
| **7. Playbook** | The attached NIST 800-61 playbook walks through detection and analysis, containment, eradication, recovery and post-incident review. Automated steps propose their action for each matching host, address or account, through the same approval queue, and the playbook advances when they finish. | The analyst makes the decisions and completes the manual steps |
| **8. Close** | The closing note is recorded, the ticket in Jira or ServiceNow is closed and the page in PagerDuty or Opsgenie is resolved. | The analyst closes the incident, as resolved or as a false positive |

Every stage writes to the incident's timeline. That timeline is what drives live updates in the browser, notifications and ticket sync, so nothing the platform does to an incident goes unrecorded or unannounced.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11+, FastAPI, SQLAlchemy (async), Celery |
| Frontend | React 18, TypeScript, Tailwind CSS, Zustand, React Query, Vite |
| Database | PostgreSQL 16, Alembic migrations |
| Broker / live updates | Redis 7 |
| AI Providers | Anthropic Claude, OpenAI, Azure OpenAI (BYOK) |
| Integrations | 27 connectors: see [Platform Integrations](#platform-integrations) |
| Deployment | Docker Compose (dev), Azure Container Apps (prod) |

## Project Structure

```
docs/
├── INTEGRATIONS.md             # Per connector: what is verified, what it needs
└── screenshots/
my-app/
├── docker-compose.yml          # PostgreSQL, Redis, backend, Celery worker + beat, frontend
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI application, startup checks
│   │   ├── config.py           # Settings (CANE_* environment variables)
│   │   ├── models/  schemas/   # SQLAlchemy models, Pydantic request/response shapes
│   │   ├── api/                # Routes
│   │   │   ├── auth.py  users.py       # Sign-in, accounts, team, API keys
│   │   │   ├── incidents.py            # Queue views, search, CRUD, assign, close, enrich
│   │   │   ├── logs.py                 # Ingest, batch, upload, query
│   │   │   ├── triage.py  actions.py   # AI analysis; approve / reject / execute
│   │   │   ├── playbooks.py            # CRUD, attach to incident, advance step
│   │   │   ├── dashboard.py  integrations.py
│   │   │   ├── events.py               # Live update stream (server-sent events)
│   │   │   └── hooks.py                # Slack approval buttons (signature-verified)
│   │   ├── services/
│   │   │   ├── log_normalizer.py       # 14 log types -> one event shape
│   │   │   ├── correlation.py          # Group events, decide when to open an incident
│   │   │   ├── log_ingestion.py        # Ingestion orchestration
│   │   │   ├── enrichment_service.py   # Threat intel and user / host context lookups
│   │   │   ├── triage_service.py       # Enrich -> LLM -> validate -> actions
│   │   │   ├── triage_guard.py         # What an LLM reply is allowed to cause
│   │   │   ├── action_service.py       # Approval workflow, fan-out to connected tools
│   │   │   ├── playbook_service.py     # Step progression, automated-step proposals
│   │   │   ├── events.py               # Change feed driven by the incident timeline
│   │   │   ├── followup_service.py     # Notifications and ticket sync
│   │   │   └── integration_service.py  # Connector lookup by ability, health
│   │   ├── ai/                         # Claude, OpenAI, Azure OpenAI, mock; prompts
│   │   ├── integrations/               # 27 connectors + base_client.py + registry.py
│   │   ├── data/seed_playbooks.py      # 7 NIST 800-61 playbooks (59 steps)
│   │   └── workers/                    # Celery: triage, follow-ups, source polling, health
│   ├── alembic/versions/       # Database migrations
│   ├── scripts/                # migrate.py, e2e_test.py, ingest_synthetic_logs.py
│   └── tests/                  # Unit tests and connector contract tests
└── frontend/src/
    ├── App.tsx                 # Routes + auth guard
    ├── useLiveUpdates.ts       # Subscribes to the event stream
    ├── api/  store/            # Axios client, Zustand auth state
    ├── components/             # App shell (icon rail + top bar), queue table, shared UI
    └── pages/                  # Dashboard, Incidents, Incident detail, Action queue,
                                # Playbooks, Logs, Settings, Login
synthetic_logs/  enhanced_synthetic_logs/   # Sample data: 14 log types, 4 attack scenarios
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

27 connectors, added under **Settings → Integrations**. A connector declares what it can do, and the platform sends work to every connected one with that ability: blocking an address reaches each firewall and EDR that is connected, isolating a host reaches whichever EDR knows it.

| Group | Connectors | What they do |
|-------|------------|--------------|
| Response | Microsoft Defender for Endpoint, Microsoft Graph, Microsoft Sentinel, CrowdStrike Falcon, SentinelOne, Okta, Palo Alto (PAN-OS), Fortinet FortiGate | Block IP / URL / file hash, isolate or release a host, antivirus scan, disable an account, revoke sessions, force a password reset, remove a phishing email from the mailboxes it reached |
| Threat intelligence | VirusTotal, AbuseIPDB, GreyNoise, urlscan.io, RDAP (domain age), GeoIP (local database), Hybrid Analysis, MISP, OpenCTI | Reputation for the IPs, domains, URLs and file hashes in an incident |
| Context | Microsoft Graph (Entra ID, Intune), Okta, Defender, CrowdStrike, SentinelOne | Who an account is (title, manager, admin role) and what a host is (owner, OS, isolation state) |
| Notifications | Slack, Microsoft Teams, PagerDuty, Opsgenie, generic signed webhook | Announce serious incidents and approval requests; resolve the page when the incident closes |
| Ticketing | Jira, ServiceNow | Open a ticket for each serious incident, mirror analyst notes, close it with the incident |
| Sources | Splunk, Elastic Security, AWS GuardDuty | Polled every minute; events flow through normal ingestion |

Credentials are AES-256-GCM encrypted at rest. New integrations start in **dry-run**: anything that would change an outside system is logged as if it ran and nothing is sent, until an admin chooses **Go live**.

**How far each connector has been verified.** Every connector has contract tests that run it against a fake HTTP layer and check the exact requests against the vendor's published API. That is not the same as having run against the real service. RDAP and the generic webhook have been exercised for real; the others need a first run against your own account, in dry-run and then live on a test asset, before you rely on them. See `docs/INTEGRATIONS.md` for what was and was not confirmed per connector.

### Approving from Slack

Approval requests posted to Slack carry Approve and Reject buttons. Set the Slack app's Interactivity Request URL to `https://<your-host>/api/v1/hooks/slack/actions`. Each click is verified against the app's signing secret, and the person clicking must have an active Cane AI account with the same email and a role that could approve in the app itself.

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Node.js 20+ (for local frontend development)
- Python 3.11+ (for local backend development)

### Quick Start with Docker

```bash
cd my-app
docker compose up --build
```

On startup the backend applies database migrations (`scripts/migrate.py`, Alembic) and loads the 7 built-in playbooks.

Create the first account. The first account ever registered becomes the administrator; after that, registration is closed and admins add people under **Settings → Team**.

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "choose-a-long-password", "full_name": "Admin"}'
```

Services will be available at:
- **Frontend**: http://localhost:5173 (set `CANE_FRONTEND_PORT` in `my-app/.env` to change it)
- **Backend API**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs

Load the sample data (14 log types plus 4 attack scenarios):

```bash
docker compose exec backend python scripts/ingest_synthetic_logs.py
```

#### Trying the pipeline without an LLM key

Set `CANE_AUTO_TRIAGE_PROVIDER=mock` in `my-app/.env`. The mock provider is a small set of fixed rules, **not an AI model**: it exists so ingestion → triage → action queue → playbook can be exercised locally at no cost. Everything it produces is labelled `mock`, and it refuses to run unless `CANE_DEBUG=true`.

### Local Development

**Backend:**
```bash
cd my-app/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start PostgreSQL and Redis (via Docker or locally)
docker compose up postgres redis -d

# Apply database migrations (also safe on a database from before migrations existed)
python scripts/migrate.py

# Start the server (built-in playbooks are loaded on startup)
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd my-app/frontend
npm install
VITE_API_TARGET=http://localhost:8000 npm run dev
```

### Environment Variables

For Docker, put these in `my-app/.env` (gitignored). For a local backend, copy `backend/.env.example` to `backend/.env`.

```env
# Required outside local development. With CANE_DEBUG=false the backend refuses to
# start while either is still the default from this repository.
CANE_JWT_SECRET_KEY=            # openssl rand -hex 32
CANE_ENCRYPTION_MASTER_KEY=     # openssl rand -hex 32
CANE_DEBUG=false

CANE_DATABASE_URL=postgresql+asyncpg://cane:cane_secret@localhost:5432/cane_db
CANE_REDIS_URL=redis://localhost:6379/0

# Automated AI triage
CANE_AUTO_TRIAGE_ENABLED=true
CANE_AUTO_TRIAGE_PROVIDER=claude          # claude, openai, azure_openai (or mock, debug only)
CANE_AUTO_TRIAGE_API_KEY=sk-ant-...       # System-level LLM API key
CANE_AUTO_TRIAGE_MODEL=                   # Optional model override (Claude default: claude-opus-5-5)
CANE_AUTO_TRIAGE_AZURE_ENDPOINT=          # Required for azure_openai

# Ingestion
CANE_INGEST_API_KEY=                      # Machine senders send this as the X-API-Key header
CANE_INCIDENT_MIN_SEVERITY=medium         # Correlated groups below this stay as logs

# Containment
CANE_AUTO_RESPONSE_CONFIDENCE_THRESHOLD=0.95
CANE_AUTO_EXECUTE_ACTION_TYPES='["block_ip","block_url","block_file_hash"]'

# Accounts
CANE_ALLOW_SELF_REGISTRATION=false        # true lets anyone self-register, as tier 1 only

# Links in notifications and tickets point here
CANE_PUBLIC_URL=https://cane.example.com
CANE_NOTIFY_MIN_SEVERITY=high             # Announce incidents at or above this severity
CANE_TICKET_MIN_SEVERITY=high             # Open tickets at or above this severity
CANE_SOURCE_POLL_SECONDS=60               # How often log sources are polled
```

### Sending logs from Sentinel (or anything else)

```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "X-API-Key: $CANE_INGEST_API_KEY" -H "Content-Type: application/json" \
  -d '{"schemaId": "securityalert", "data": {"TimeGenerated": "2026-11-21T08:29:00Z", "DisplayName": "Malware detected", "AlertSeverity": "High"}}'
```

## How auto-containment is gated

Log content is attacker-controlled (email subjects, URLs, user names, command lines) and it goes into the LLM prompt, so the model's reply is treated as untrusted. For every action the model recommends:

| Check | If it fails |
|-------|-------------|
| The action is one the AI may propose (block IP/URL/hash, isolate host, AV scan, disable account, revoke sessions, force password reset). Re-enabling an account, releasing a host and free-form KQL are analyst-only. | Dropped |
| The target literally appears in the incident's own events, and an IP to block is a public address | Dropped |
| The action type is on `CANE_AUTO_EXECUTE_ACTION_TYPES` | Queued for approval |
| The model marked it auto-executable and did **not** ask for human review | Queued for approval |
| Confidence is a number in 0-1 at or above the threshold | Queued for approval |
| Triage ran automatically (analyst-triggered triage never executes anything) | Queued for approval |

Dropped suggestions are kept on the analysis with the reason and shown on the incident page. A reply that fails validation is recorded as a failed triage and the incident goes to an analyst. Integrations default to **dry-run**, where actions are logged as if they ran and nothing is changed, until an admin chooses **Go live**.

## Testing

```bash
# Unit tests: the guard, normalisation, incident rules
docker compose exec backend python -m pytest tests -q

# End-to-end against the running stack (69 checks: auth, RBAC, ingestion,
# correlation, triage, action approval, playbooks, incident lifecycle)
CANE_E2E_EMAIL=admin@example.com CANE_E2E_PASSWORD=... python my-app/backend/scripts/e2e_test.py --ai
```

`--ai` requires the triage steps to pass; it needs a funded LLM key or the mock provider. The script signs in with the admin account given in `CANE_E2E_EMAIL` and `CANE_E2E_PASSWORD`.

## Known gaps

- **Integrations are verified against published APIs, not live accounts** (see Platform Integrations above).
- **Multi-tenancy**: `tenant_id` is stored but nothing filters by it. Treat a deployment as single-tenant.
- **Audit trail**: actions and incident changes are on each incident's timeline. Logins, role changes and integration edits are not yet recorded in the `audit_trail` table.
- **Sessions**: refresh tokens are not revocable individually. Deactivating an account blocks its tokens immediately.
- **Slack approvals need a public URL** for Slack to call. Teams notifications are link-only: a Teams webhook cannot receive button clicks.
- **GeoIP needs a database file** you download yourself (MaxMind GeoLite2 or DB-IP Lite, `.mmdb`), with its path set on the integration.

## API Overview

| Endpoint Group | Routes | Description |
|---------------|--------|-------------|
| `/api/v1/auth` | 3 | Register (first account / admin only), login, refresh token |
| `/api/v1/users` | 9 | Profile, team management (create, role, deactivate), API keys |
| `/api/v1/logs` | 5 | Ingest, batch, upload, query, schemas |
| `/api/v1/incidents` | 10 | Queue views with counts, search, CRUD, assign, escalate, close, timeline, evidence, notes |
| `/api/v1/triage` | 4 | AI analyze, results, recommendations, correlate |
| `/api/v1/playbooks` | 9 | CRUD, steps, attach to incident, advance step |
| `/api/v1/actions` | 4 | Execute, approve, reject, history |
| `/api/v1/dashboard` | 4 | Overview, threats, geo, timeline |
| `/api/v1/integrations` | 8 | CRUD, platforms, test, health |
| `/api/v1/events` | 1 | Live update stream (server-sent events) |
| `/api/v1/hooks` | 1 | Slack approval buttons (signature-verified) |

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

- First-account bootstrap, then admin-created accounts. The role in a registration request is ignored unless an admin sends it.
- The backend refuses to start with the default JWT or encryption secrets unless `CANE_DEBUG=true`.
- JWT access tokens (15 min) and refresh tokens (7 days); deactivated accounts are rejected on every request.
- AES-256-GCM encryption for stored API keys and integration credentials.
- Role checks on every endpoint; containment needs tier 2+, playbook edits manager+, integrations and people admin.
- LLM output is validated and gated before it can cause an action (see above).
- Targets are URL-encoded before being placed in integration API paths.
- Batch and upload size limits on ingestion; malformed events are rejected individually.

## License

MIT
