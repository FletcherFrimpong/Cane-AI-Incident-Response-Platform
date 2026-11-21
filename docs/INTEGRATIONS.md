# Integrations: what is verified and what is not

Every connector has **contract tests**: it is run against a fake HTTP layer and the exact requests it sends (URL, method, auth header, body) are checked against the vendor's published API. That catches most mistakes, but it is not a run against the real service.

Three levels are used below:

- **Live**: exercised against the real service from this codebase.
- **Docs**: request and response shapes confirmed against the vendor's official documentation, OpenAPI spec or official SDK source.
- **Unconfirmed**: written from general knowledge of the API; the vendor's reference could not be reached (often because it sits behind a customer login).

Before relying on any connector: connect it in **dry-run**, use **Test connection**, then go live against a test asset (a throwaway user, a lab VM, a test channel) and watch one action succeed.

Run the tests with `docker compose exec backend python -m pytest tests/integrations -q`.

## Response

| Connector | Actions | Level | Needs | Still unconfirmed |
|---|---|---|---|---|
| Microsoft Defender for Endpoint | block IP / URL / file hash, isolate, release, AV scan, describe host | Docs (machine lookup); the action endpoints predate this review | App permissions `Machine.Read.All`, `Machine.Isolate`, `Machine.Scan`, `Ti.ReadWrite` | Indicator and isolate request bodies were not re-checked against current docs |
| Microsoft Graph | disable / enable account, revoke sessions, force password reset, remove email, describe user, describe host (Intune) | Docs for message move, managed devices, role membership | `User.ReadWrite.All` (or the narrower enable/disable and revoke permissions), `User.Read.All`, `Mail.ReadWrite`, `DeviceManagementManagedDevices.Read.All` | `$filter` on `internetMessageId` and on `deviceName`; `GET /users/{id}/manager` |
| Microsoft Sentinel | run KQL query (analyst only) | Predates this review | Log Analytics reader on the workspace | Not re-checked |
| CrowdStrike Falcon | isolate (contain), release, describe host | Docs via CrowdStrike's own SDK (falconpy) and PSFalcon | API client with Hosts: Read and Hosts: Write | Case sensitivity of the hostname filter; shape of an error on a 2xx reply |
| SentinelOne | isolate (disconnect), release, scan, describe host | Docs via SentinelOne's published API reference | `Endpoints.view`, `disconnectFromNetwork`, `reconnectToNetwork`, `initiateScan` | The `networkStatus` values used to report isolation |
| Okta | suspend, unsuspend, clear sessions, expire password, describe user | Docs via Okta's OpenAPI spec | API token from an admin who can manage users | Profile attribute names for title, department and manager |
| Palo Alto (PAN-OS) | block IP | Docs for the User-ID tag registration message | Admin role with XML API User-ID Agent; **a Dynamic Address Group matching tag `cane-blocked` already used in a deny rule** | Exact wording of the "already registered" reply |
| Fortinet FortiGate | block IP (banned-IP list) | Docs via Fortinet's Ansible collection | REST API admin with write access to User & Device | Whether `expiry` is in seconds; behaviour when it is omitted |

How host actions find the machine: logs carry hostnames, vendors want device IDs. Each EDR connector looks the hostname up first (full name, then short name) and reports "not found" rather than guessing. With several EDRs connected, the action goes to all of them and succeeds if any one knows the host.

Removing an email moves it to Deleted Items in each recipient's mailbox (a soft delete the user could undo). It does not purge Recoverable Items.

## Notifications and paging

| Connector | Level | Needs | Still unconfirmed |
|---|---|---|---|
| Slack | Docs for `chat.postMessage`, `users.info`, `auth.test`, request signing | Bot token with `chat:write`, `users:read`, `users:read.email`; signing secret; channel | Block size limits; field paths in the button-click payload |
| Microsoft Teams | Docs for the Adaptive Card webhook envelope | A **Workflows** webhook URL (the older Office 365 connector webhooks have been retired) | Card element shapes; success status code |
| PagerDuty | Docs for Events API v2 | An Events v2 routing key | EU-region endpoint is not handled |
| Opsgenie | Docs for the Alert API | API key; `region` of `us` or `eu` | Whether a team-scoped key can pass the connection test |
| Generic webhook | **Live** (local listener) | An `https://` URL; optional signing secret | Nothing: you own both ends |

One PagerDuty alert is kept per incident, so a later approval request updates that alert rather than paging again.

The webhook body is the notification as JSON. With a secret set, the header `X-Cane-Signature: sha256=<hex>` is the HMAC-SHA256 of the exact body bytes.

## Ticketing

| Connector | Level | Needs | Still unconfirmed |
|---|---|---|---|
| Jira Cloud | Docs via Atlassian's OpenAPI spec | Site URL, account email, API token, `project_key` | Workflows that require a resolution on the closing transition will be rejected |
| ServiceNow | Docs for the Table API | Instance URL, username, password | Field names for notes and close code; the close code value is instance-specific (configurable) |

Tickets are opened for incidents at or above `CANE_TICKET_MIN_SEVERITY`, analyst notes are added as comments, and the ticket is closed when the incident is.

## Threat intelligence

| Connector | Looks up | Level | Needs | Still unconfirmed |
|---|---|---|---|---|
| VirusTotal | IP, domain, URL, file hash | Predates this review | API key | Not re-checked |
| AbuseIPDB | IP | Predates this review | API key | Not re-checked |
| GreyNoise | IP | **Live** (Community API, no key) | Nothing; a key lifts the rate limit | Nothing |
| RDAP (domain age) | domain | **Live** | Nothing | Reply for unsupported top-level domains |
| urlscan.io | URL, domain | **Live** for search; verdicts need a key | API key in practice: without one it can find past scans but cannot read their verdicts | Verdict field names on the result document |
| GeoIP | IP | Unconfirmed | A MaxMind-format `.mmdb` file (GeoLite2 or DB-IP Lite) and its path in `database_path` | Reader calls and record keys were written from memory |
| Hybrid Analysis | file hash | Docs via a third-party integration's source | API key | Several response fields; lookup by MD5 or SHA-1 |
| MISP | IP, domain, URL, file hash | Docs via MISP's OpenAPI spec | Base URL, API key | Nothing notable |
| OpenCTI | IP, domain, URL, file hash | Docs via OpenCTI's GraphQL schema | Base URL, API token | How search treats long URLs; the score thresholds (70 malicious, 40 suspicious) are a choice |

What leaves the platform: a lookup sends the indicator itself (an IP, domain, URL or hash from the incident) to that service. urlscan lookups only search existing scans; the connector never submits a URL for scanning, because that would publish it. Connect only the services you are comfortable sharing indicators with.

GreyNoise is the fastest way to close a false positive: an address it classifies as internet-wide scanning or a known benign service is hitting everyone, not targeting you.

## Log and alert sources

| Connector | Level | Needs | Still unconfirmed |
|---|---|---|---|
| Splunk | Docs for the search job endpoint and token auth | Management URL, token, an SPL `search` | The default search assumes Enterprise Security's notable events; self-signed management certificates will fail TLS verification |
| Elastic Security | Docs for API-key auth and the alert schema | Base URL, encoded API key | Default index covers the default Kibana space only; set `index` to `.alerts-security.alerts-*` for all spaces |
| AWS GuardDuty | Docs for ListFindings / GetFindings; request signing checked against AWS's own SigV4 test vectors | Access key, secret, region, `detector_id` | The severity bands used to map GuardDuty's numeric score |

Sources are polled every `CANE_SOURCE_POLL_SECONDS`. Each remembers where it got to and which events it has already taken, so nothing is ingested twice. The last poll time, count and any error show on the integration under Settings.
