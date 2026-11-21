"""End-to-end test of the Cane AI pipeline against a running stack.

Drives the real HTTP API the way an operator and an analyst would:
register -> ingest a correlated attack scenario -> incident created ->
(auto-)triage -> action queue -> approve/reject -> playbook -> close.

Usage:
    python scripts/e2e_test.py [--base http://localhost:8000] [--ai]

--ai   also require the LLM-backed steps (needs CANE_AUTO_TRIAGE_API_KEY on the
       backend and worker). Without it those steps are reported as skipped.

Uses only the standard library so it runs from the host without the venv.
Every run uses a unique correlation ID, so it never collides with old data.
"""

import argparse
import os
import json
import sys
import time
import urllib.error
import urllib.request
import uuid

RESULTS: list[tuple[str, str, str]] = []


def record(name: str, status: str, detail: str = ""):
    RESULTS.append((name, status, detail))
    mark = {"PASS": "\033[32mPASS\033[0m", "FAIL": "\033[31mFAIL\033[0m", "SKIP": "\033[33mSKIP\033[0m"}[status]
    print(f"  {mark}  {name}" + (f"  -- {detail}" if detail else ""))


def check(name: str, condition: bool, detail: str = ""):
    record(name, "PASS" if condition else "FAIL", detail if not condition else "")
    return condition


class Api:
    def __init__(self, base: str):
        self.base = base.rstrip("/") + "/api/v1"
        self.token: str | None = None

    def call(self, method: str, path: str, body=None, token: str | None = "default", raw: bytes | None = None,
             headers: dict | None = None):
        url = self.base + path
        hdrs = {"Content-Type": "application/json"}
        tok = self.token if token == "default" else token
        if tok:
            hdrs["Authorization"] = f"Bearer {tok}"
        if headers:
            hdrs.update(headers)
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                text = resp.read().decode()
                return resp.status, (json.loads(text) if text else None)
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            try:
                return e.code, json.loads(text)
            except json.JSONDecodeError:
                return e.code, {"raw": text[:300]}


def scenario_events(cid: str) -> list[dict]:
    """A small ransomware scenario: 5 correlated events sharing one correlation ID."""
    t = "2026-11-21T08:2{}:00.000Z"
    common = {"TenantId": "e2e-tenant", "CorrelationId": cid}
    return [
        {"schemaId": "securityalert", "data": {**common, "TimeGenerated": t.format(9),
            "DisplayName": "Ransomware Activity Detected - WannaCry Variant",
            "AlertName": "Ransomware_Activity_Detected", "AlertSeverity": "Critical",
            "Description": "Multiple indicators of ransomware activity. Files being encrypted with .wcry extension.",
            "ProviderName": "Microsoft Defender for Endpoint", "CompromisedEntity": "webserver-01.contoso.com",
            "Tactics": "Impact, Execution"}},
        {"schemaId": "securityevent", "data": {**common, "TimeGenerated": t.format(5), "EventID": 4688,
            "Computer": "webserver-01.contoso.com", "Activity": "A new process has been created",
            "SubjectUserName": "admin", "NewProcessName": "C:\\Windows\\Temp\\wcry.exe",
            "CommandLine": "wcry.exe /encrypt /silent", "IpAddress": "185.220.101.42"}},
        {"schemaId": "commonsecuritylog", "data": {**common, "TimeGenerated": t.format(6),
            "DeviceVendor": "Palo Alto Networks", "DeviceProduct": "PAN-OS", "Activity": "Threat detected",
            "LogSeverity": "Critical", "SourceIP": "185.220.101.42", "DestinationIP": "10.0.1.15",
            "DestinationPort": 445, "DeviceAction": "Deny"}},
        {"schemaId": "dnsevents", "data": {**common, "TimeGenerated": t.format(8),
            "Computer": "webserver-01.contoso.com", "QueryName": "wcry-killswitch.com", "QueryType": "A",
            "SourceIP": "10.0.1.15", "ClientIP": "10.0.1.15"}},
        {"schemaId": "signinlogs", "data": {**common, "TimeGenerated": t.format(4),
            "UserPrincipalName": "admin@contoso.com", "IPAddress": "185.220.101.42",
            "ResultType": "0", "Location": "RU", "RiskLevelDuringSignIn": "high"}},
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--ai", action="store_true", help="require LLM-backed steps to pass")
    args = ap.parse_args()

    api = Api(args.base)
    run = uuid.uuid4().hex[:8]
    cid = f"e2e-ransomware-{run}"
    print(f"Cane AI end-to-end test  (run {run}, base {args.base})\n")

    # ---------------------------------------------------------------- auth
    print("Auth & access control")
    code, _ = api.call("GET", "/incidents/", token=None)
    check("unauthenticated request is rejected with 401", code == 401, f"got {code}")

    pw = f"E2e-{run}-Passw0rd!"
    admin_email = f"e2e-admin-{run}@example.com"
    admin_login = os.environ.get("CANE_E2E_EMAIL", "demo@cane.ai")
    admin_password = os.environ.get("CANE_E2E_PASSWORD")
    if not admin_password:
        print("Set CANE_E2E_PASSWORD (and optionally CANE_E2E_EMAIL) to an admin account's credentials.")
        return 2
    code, body = api.call("POST", "/auth/login", {"email": admin_login, "password": admin_password}, token=None)
    if code != 200:
        record("login as admin", "FAIL", f"{code} {body}")
        return summary()
    api.token = body["access_token"]
    refresh = body["refresh_token"]
    record("login as admin", "PASS")

    code, body = api.call("POST", "/auth/register",
                          {"email": admin_email, "password": pw, "full_name": "E2E", "role": "admin"}, token=None)
    check("anonymous self-registration as admin is refused", code in (401, 403) or
          (code == 200 and _role_of(api, body.get("access_token")) != "admin"),
          f"got {code}; anyone can mint an admin account")

    t1_email = f"e2e-t1-{run}@example.com"
    code, body = api.call("POST", "/users/", {"email": t1_email, "password": pw, "full_name": "E2E Tier1",
                                             "role": "tier1_analyst"})
    check("admin can create a tier-1 analyst account", code == 201 and body.get("role") == "tier1_analyst",
          f"{code} {body}")
    t1_id = body.get("id") if code == 201 else None
    code, body = api.call("POST", "/auth/login", {"email": t1_email, "password": pw}, token=None)
    tier1 = body.get("access_token") if code == 200 else None
    check("the new analyst can sign in", tier1 is not None, f"{code} {body}")
    code, _ = api.call("POST", "/auth/login", {"email": t1_email, "password": "wrong-password"}, token=None)
    check("wrong password is rejected with 401", code == 401, f"got {code}")
    code, _ = api.call("GET", "/users/", token=tier1)
    check("tier-1 analyst cannot list users (403)", code == 403, f"got {code}")

    code, body = api.call("POST", "/auth/refresh", {"refresh_token": refresh}, token=None)
    check("refresh token issues a new access token", code == 200 and "access_token" in (body or {}), f"{code}")
    code, _ = api.call("GET", "/users/me", token=refresh)
    check("refresh token cannot be used as an access token", code == 401, f"got {code}")
    code, me = api.call("GET", "/users/me")
    check("GET /users/me returns the profile", code == 200 and me.get("email") == admin_login, f"{code}")

    # ----------------------------------------------------------- ingestion
    print("\nIngestion, normalisation & correlation")
    events = scenario_events(cid)
    code, body = api.call("POST", "/logs/batch", {"events": events})
    ok = check("batch ingest of 5 correlated events", code == 200 and body.get("ingested") == 5, f"{code} {body}")
    if not ok:
        return summary()
    check("batch reports exactly 1 new incident", body.get("incidents_created") == 1, f"{body}")

    code, body = api.call("GET", f"/logs/?correlation_id={cid}")
    logs = body.get("items", []) if code == 200 else []
    check("all 5 events are stored and queryable", len(logs) == 5, f"{code}, {len(logs)} found")
    check("every event is linked to an incident", bool(logs) and all(l.get("incident_id") for l in logs))
    sev = {l["log_type"]: l["severity"] for l in logs}
    check("SecurityAlert normalised to critical severity", sev.get("SecurityAlert") == "critical", f"{sev}")

    incident_id = logs[0]["incident_id"] if logs else None
    code, inc = api.call("GET", f"/incidents/{incident_id}")
    check("incident exists", code == 200, f"{code}")
    if code != 200:
        return summary()
    check("incident severity = critical (highest of its events)", inc["severity"] == "critical", inc["severity"])
    check("incident attack type detected as ransomware", inc["attack_type"] == "ransomware", str(inc["attack_type"]))
    check("incident title taken from the SecurityAlert", "Ransomware" in inc["title"], inc["title"])
    check("attacker IP captured in source entities",
          "185.220.101.42" in (inc.get("source_entities") or {}).get("ips", []), str(inc.get("source_entities")))

    code, body = api.call("POST", "/logs/ingest", events[2])
    check("late event with same correlation ID joins the same incident",
          code == 200 and body.get("incident_id") == incident_id, f"{code} {body}")
    code, body = api.call("POST", "/logs/batch", {"events": events[:2]})
    check("re-ingest into an existing incident reports 0 new incidents",
          code == 200 and body.get("incidents_created") == 0, f"{body}")

    noise_cid = f"e2e-noise-{run}"
    quiet = {"schemaId": "signinlogs", "data": {
        "TenantId": "e2e-tenant", "TimeGenerated": "2026-11-21T08:00:00Z", "CorrelationId": noise_cid,
        "UserPrincipalName": "alice@contoso.com", "IPAddress": "198.51.100.7", "ResultType": "0"}}
    code, body = api.call("POST", "/logs/ingest", quiet)
    check("a routine informational sign-in does not open an incident",
          code == 200 and body.get("incident_id") is None, f"{code} {body}")
    code, body = api.call("POST", "/logs/ingest", {"schemaId": "securityalert", "data": {
        "TenantId": "e2e-tenant", "TimeGenerated": "2026-11-21T08:05:00Z", "CorrelationId": noise_cid,
        "DisplayName": "Impossible travel sign-in", "AlertSeverity": "High"}})
    escalated = body.get("incident_id") if code == 200 else None
    check("a later high-severity alert on the same correlation ID opens one", bool(escalated), f"{code} {body}")
    code, body = api.call("GET", f"/logs/?correlation_id={noise_cid}")
    check("the earlier quiet event is pulled into that incident",
          code == 200 and len(body["items"]) == 2 and all(l["incident_id"] == escalated for l in body["items"]),
          f"{code}")
    code, body = api.call("POST", "/logs/ingest", {"schemaId": "securityalert", "data": {
        "TenantId": "e2e-tenant", "TimeGenerated": "2026-11-21T08:06:00Z",
        "DisplayName": "Malware detected on host", "AlertSeverity": "High"}})
    check("a serious alert with no correlation ID still becomes an incident",
          code == 200 and body.get("incident_id"), f"{code} {body}")
    code, body = api.call("POST", "/logs/batch", {"events": [quiet, {"schemaId": "signinlogs", "data": {
        "TimeGenerated": "garbage", "CorrelationId": noise_cid}}]})
    check("a bad event in a batch is reported and the rest still ingested",
          code == 200 and body.get("ingested") == 1 and body.get("errors") == 1, f"{code} {body}")

    code, body = api.call("GET", f"/incidents/{incident_id}/evidence")
    n_ev = len(body.get("events", body) if isinstance(body, dict) else body) if code == 200 else 0
    check("incident evidence lists the linked events", code == 200 and n_ev >= 5, f"{code}, {n_ev} events")

    code, body = api.call("POST", "/logs/ingest", {"schemaId": "securityalert", "data": {"TimeGenerated": "not-a-date"}})
    check("malformed event is rejected with 422, not a crash", code == 422, f"got {code}")

    # ---------------------------------------------------------- AI triage
    print("\nAI triage & auto-containment")
    analysis = None
    deadline = time.time() + 90
    while time.time() < deadline:
        code, body = api.call("GET", f"/triage/{incident_id}")
        if code == 200 and body:
            analysis = body[0]
            break
        if not args.ai and time.time() > deadline - 80:
            break
        time.sleep(3)

    if analysis is None:
        if args.ai:
            record("automatic triage ran after ingestion", "FAIL", "no AI analysis appeared within 90s")
        else:
            record("automatic triage ran after ingestion", "SKIP", "no LLM key configured (run with --ai to require)")
    else:
        record("automatic triage ran after ingestion", "PASS")
        out = analysis["output"]
        check("triage output is structured (severity, summary, actions)",
              all(k in out for k in ("severity", "summary", "recommended_actions")), str(list(out)))
        check("the guard recorded a decision for every recommended action",
              len(out.get("action_decisions", [])) == len(out.get("recommended_actions", [])))
        check("triage classifies the scenario as ransomware", "ransom" in str(out.get("attack_type", "")).lower(),
              str(out.get("attack_type")))
        check("triage maps MITRE ATT&CK techniques", bool(out.get("mitre_techniques")), str(out.get("mitre_techniques")))
        code, inc = api.call("GET", f"/incidents/{incident_id}")
        check("incident still loads after triage (no 500)", code == 200, f"{code} {str(inc)[:200]}")
        if code == 200:
            check("incident moved out of 'new' after triage", inc["status"] != "new", inc["status"])
            check("incident confidence score recorded", inc.get("confidence_score") is not None)
        code, body = api.call("GET", f"/incidents/?page=1&page_size=5")
        check("incident list still loads after triage (no 500)", code == 200, f"{code}")

    code, actions = api.call("GET", f"/actions/history?incident_id={incident_id}")
    actions = actions if code == 200 else []
    if analysis is not None:
        check("triage produced response actions for the incident", len(actions) > 0, f"{len(actions)} actions")
        executed = [a for a in actions if a["status"] in ("completed", "executing")]
        check("no containment action ran against a real system without an integration", not executed,
              f"{[a['action_type'] for a in executed]}")
        targets = {(a["action_type"], json.dumps(a["action_params"], sort_keys=True)) for a in actions}
        check("no duplicate actions (same type + target)", len(targets) == len(actions))

    # ------------------------------------------------------ action workflow
    print("\nAnalyst action workflow")
    code, body = api.call("POST", "/actions/execute", {"incident_id": incident_id, "action_type": "block_ip",
                                                       "action_params": {"ip_address": "185.220.101.42"}}, token=tier1)
    check("tier-1 analyst cannot execute containment actions (403)", code == 403, f"got {code}")

    code, body = api.call("POST", "/actions/execute", {"incident_id": incident_id, "action_type": "block_ip",
                                                       "action_params": {"ip_address": "203.0.113.77"}})
    check("tier-2+ execute without a Defender integration fails cleanly",
          code == 200 and body["status"] == "failed" and "integration" in (body.get("error_message") or "").lower(),
          f"{code} {str(body)[:200]}")

    code, body = api.call("POST", "/actions/execute", {"incident_id": incident_id, "action_type": "format_all_disks",
                                                       "action_params": {}})
    check("unknown action type is rejected", (code == 200 and body["status"] == "failed") or code in (400, 422),
          f"{code} {str(body)[:150]}")

    code, pending = api.call("GET", "/actions/pending")
    mine = [a for a in (pending or []) if a["incident_id"] == incident_id] if code == 200 else []
    if mine:
        a = mine[0]
        code, _ = api.call("POST", f"/actions/{a['id']}/approve", {"notes": "x"}, token=tier1)
        check("tier-1 analyst cannot approve actions (403)", code == 403, f"got {code}")
        code, body = api.call("POST", f"/actions/{a['id']}/reject", {"reason": "e2e test rejection"})
        check("pending action can be rejected", code == 200 and body["status"] == "rejected", f"{code}")
        code, body = api.call("POST", f"/actions/{a['id']}/approve", {"notes": "x"})
        check("rejected action cannot then be approved", code in (400, 403, 409), f"got {code}")
        if len(mine) > 1:
            b = mine[1]
            code, body = api.call("POST", f"/actions/{b['id']}/approve", {"notes": "e2e approve"})
            check("approving without an integration fails cleanly (not 500, not 'completed')",
                  code == 200 and body["status"] == "failed", f"{code} {str(body)[:200]}")
    else:
        record("approve / reject pending actions", "SKIP", "no pending AI-recommended actions (needs triage)")

    # ----------------------------------------------------------- playbooks
    print("\nPlaybooks")
    code, pbs = api.call("GET", "/playbooks/")
    pbs = pbs if code == 200 else []
    check("built-in NIST playbooks are present (7)", len([p for p in pbs if p.get("is_builtin")]) >= 7,
          f"{len(pbs)} playbooks, {len([p for p in pbs if p.get('is_builtin')])} built-in")
    ransomware_pb = next((p for p in pbs if "ransomware" in (p.get("attack_types") or [])), None)
    if ransomware_pb:
        code, detail = api.call("GET", f"/playbooks/{ransomware_pb['id']}")
        check("ransomware playbook has its steps", code == 200 and len(detail.get("steps", [])) >= 5,
              f"{code}")
        code, body = api.call("POST", f"/playbooks/{ransomware_pb['id']}/execute/{incident_id}")
        check("playbook can be started on the incident", code == 200, f"{code} {str(body)[:200]}")
        code, inc = api.call("GET", f"/incidents/{incident_id}")
        check("incident records the attached playbook", code == 200 and inc.get("playbook_id") == ransomware_pb["id"],
              f"{code}")
    else:
        record("ransomware playbook run", "SKIP", "no ransomware playbook in the database")

    code, body = api.call("POST", "/playbooks/", {"name": f"E2E custom {run}", "attack_types": ["e2e"]}, token=tier1)
    check("tier-1 analyst cannot create playbooks (403)", code == 403, f"got {code}")
    code, pb = api.call("POST", "/playbooks/", {"name": f"E2E custom {run}", "attack_types": ["e2e"]})
    if check("manager+ can create a custom playbook", code == 201, f"{code} {str(pb)[:150]}"):
        code, st = api.call("POST", f"/playbooks/{pb['id']}/steps", {
            "step_order": 1, "phase": "containment", "title": "Block", "description": "Block the IP",
            "step_type": "human_action"})
        check("step can be added to the playbook", code == 201, f"{code} {str(st)[:150]}")
        code, _ = api.call("DELETE", f"/playbooks/{pb['id']}")
        check("custom playbook can be deleted", code in (200, 204), f"{code}")

    # --------------------------------------------------- playbook automation
    print("\nPlaybook automation")
    if ransomware_pb:
        # Walk to the first automated step (isolate hosts) and check it proposes actions.
        proposed = None
        for _ in range(6):
            code, inc = api.call("GET", f"/incidents/{incident_id}")
            code, detail = api.call("GET", f"/playbooks/{ransomware_pb['id']}")
            current = next((s for s in detail["steps"] if s["step_order"] == inc.get("current_playbook_step")), None)
            if current and current["step_type"] == "automated":
                proposed = current
                break
            api.call("POST", f"/playbooks/advance/{incident_id}", {"decision": "CONFIRMED"})
        check("playbook reaches an automated step", proposed is not None)
        if proposed:
            code, acts = api.call("GET", f"/actions/history?incident_id={incident_id}")
            mine = [a for a in acts if a["action_type"] == proposed["auto_action_type"]
                    and a["status"] == "pending_approval"]
            check(f"automated step proposes '{proposed['auto_action_type']}' for approval, not execution",
                  len(mine) >= 1, f"{[(a['action_type'], a['status']) for a in acts]}")
            if mine:
                host = list(mine[0]["action_params"].values())[0]
                check("the proposed target comes from the incident's own evidence",
                      host in ("webserver-01.contoso.com",), str(host))
                code, body = api.call("POST", f"/actions/{mine[0]['id']}/approve", {"notes": "e2e"})
                check("approving it without an EDR connected fails with a clear reason",
                      code == 200 and body["status"] == "failed" and "Connect one of" in (body.get("error_message") or ""),
                      f"{code} {str(body.get('error_message'))[:160]}")
                code, inc2 = api.call("GET", f"/incidents/{incident_id}")
                check("a failed action does not advance the playbook",
                      inc2.get("current_playbook_step") == proposed["step_order"], str(inc2.get("current_playbook_step")))

    # ------------------------------------------------------------ live updates
    print("\nLive updates")
    import threading
    got: list[str] = []

    def listen():
        req = urllib.request.Request(api.base + "/events/stream", headers={"Authorization": f"Bearer {api.token}"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                for raw in resp:
                    line = raw.decode().strip()
                    if line.startswith("data: "):
                        got.append(line[6:])
                        return
        except Exception as e:  # noqa: BLE001
            got.append(f"error: {e}")

    listener = threading.Thread(target=listen, daemon=True)
    listener.start()
    time.sleep(1.0)
    api.call("POST", f"/incidents/{incident_id}/notes", {"content": "e2e live update probe"})
    listener.join(timeout=10)
    check("an open stream is told at once when the incident changes",
          bool(got) and incident_id in got[0], str(got[:1]))
    code, _ = api.call("GET", "/events/stream", token=None)
    check("the event stream requires sign-in (401)", code == 401, f"got {code}")

    # ---------------------------------------------------- incident lifecycle
    print("\nIncident lifecycle")
    code, body = api.call("POST", f"/incidents/{incident_id}/notes", {"content": "e2e analyst note"})
    check("analyst note can be added", code in (200, 201), f"{code}")
    code, body = api.call("PUT", f"/incidents/{incident_id}/assign", {"user_id": me["id"]})
    check("incident can be assigned", code == 200 and body.get("assigned_to") == me["id"], f"{code}")
    code, body = api.call("PUT", f"/incidents/{incident_id}/escalate")
    check("incident can be escalated", code == 200, f"{code} {str(body)[:150]}")
    code, tl = api.call("GET", f"/incidents/{incident_id}/timeline")
    types = [t["event_type"] for t in tl] if code == 200 else []
    check("timeline records creation, note and assignment",
          code == 200 and "incident_created" in types and len(types) >= 3, f"{types}")
    code, body = api.call("PUT", f"/incidents/{incident_id}/close", {"content": "e2e: contained and resolved"})
    check("incident can be closed", code == 200 and body.get("status") in ("closed", "false_positive"),
          f"{code} {str(body)[:200]}")
    check("closed incident has a resolved_at timestamp", code == 200 and body.get("resolved_at") is not None)

    # ------------------------------------------------------------ dashboard
    print("\nDashboard & integrations")
    for path in ("overview", "threats", "geo", "timeline"):
        code, body = api.call("GET", f"/dashboard/{path}")
        check(f"dashboard/{path} responds", code == 200, f"{code}")
    code, body = api.call("GET", "/integrations/platforms")
    check("all 27 connectors are advertised, in five groups",
          code == 200 and len(body) == 27
          and {p["category"] for p in body} == {"response", "enrichment", "notification", "ticketing", "source"},
          f"{code}, {len(body) if code == 200 else 0} connectors")
    code, body = api.call("POST", "/integrations/", {"platform": "abuseipdb", "display_name": "x",
                                                     "auth_type": "api_key", "credentials": {"api_key": "k"}},
                          token=tier1)
    check("tier-1 analyst cannot add integrations (403)", code == 403, f"got {code}")

    if t1_id:
        code, _ = api.call("PUT", f"/users/{t1_id}/active", {"is_active": False})
        code2, _ = api.call("GET", "/users/me", token=tier1)
        check("a deactivated account's token stops working", code == 200 and code2 == 401, f"{code}/{code2}")

    return summary()


def _role_of(api: Api, token: str | None) -> str | None:
    if not token:
        return None
    code, body = api.call("GET", "/users/me", token=token)
    return body.get("role") if code == 200 else None


def summary() -> int:
    passed = sum(1 for _, s, _ in RESULTS if s == "PASS")
    failed = [(n, d) for n, s, d in RESULTS if s == "FAIL"]
    skipped = sum(1 for _, s, _ in RESULTS if s == "SKIP")
    print(f"\n{passed} passed, {len(failed)} failed, {skipped} skipped")
    for n, d in failed:
        print(f"  FAILED: {n}" + (f" -- {d}" if d else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
