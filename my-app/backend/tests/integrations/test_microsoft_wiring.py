"""The Microsoft connectors as the platform calls them: OAuth token request, and
host actions that start from a hostname found in the logs."""

import httpx

from app.integrations.microsoft_defender import MicrosoftDefenderClient
from app.integrations.microsoft_graph import MicrosoftGraphClient
from tests.integrations.helpers import Recorder

CREDS = {"tenant_id": "t-1", "client_id": "app-1", "client_secret": "s3cret"}
MACHINE_ID = "a" * 40


def defender(handler, dry_run=False):
    client = MicrosoftDefenderClient(credentials=CREDS, dry_run=dry_run)
    rec = Recorder(handler)
    rec.attach(client)
    return client, rec


def handler(request: httpx.Request) -> httpx.Response:
    if "oauth2" in request.url.path:
        return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    if request.url.path.endswith("/machines"):
        return httpx.Response(200, json={"value": [{"id": MACHINE_ID, "computerDnsName": "web-01.contoso.com",
                                                    "lastSeen": "2026-11-21T10:00:00Z"}]})
    return httpx.Response(201, json={"id": "action-1", "status": "Pending"})


async def test_token_request_is_sent_as_a_form():
    client, rec = defender(handler)
    await client.isolate_host(machine_id="web-01.contoso.com")
    token_request = rec.requests[0]
    assert token_request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert b"grant_type=client_credentials" in token_request.content and b"client_id=app-1" in token_request.content


async def test_isolate_host_resolves_the_hostname_then_isolates_that_machine():
    client, rec = defender(handler)
    result = await client.isolate_host(machine_id="web-01.contoso.com")
    assert result["success"] is True
    assert rec.last.method == "POST" and rec.last.url.path.endswith(f"/machines/{MACHINE_ID}/isolate")
    assert any(p.endswith("/machines") for p in rec.paths())  # looked the hostname up first


async def test_unknown_host_is_not_found_and_nothing_is_isolated():
    def nothing(request):
        if "oauth2" in request.url.path:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return httpx.Response(200, json={"value": []})

    client, rec = defender(nothing)
    result = await client.isolate_host(machine_id="ghost-99")
    assert result["success"] is False and result["not_found"] is True
    assert not any(r.method == "POST" and "isolate" in r.url.path for r in rec.requests)


async def test_dry_run_touches_nothing():
    client, rec = defender(handler, dry_run=True)
    for call in (client.isolate_host, client.release_host, client.scan_host):
        assert (await call(machine_id="web-01.contoso.com"))["dry_run"] is True
    assert rec.requests == []


def test_declared_actions_exist_and_take_the_platform_parameter():
    import inspect

    from app.integrations.registry import INTEGRATION_REGISTRY
    from app.services.action_service import ACTION_EXTRA_PARAMS, ACTION_PARAM_KEYS

    for name, cls in INTEGRATION_REGISTRY.items():
        for action, method_name in cls.actions.items():
            assert action in ACTION_PARAM_KEYS, f"{name}: unknown action {action}"
            params = inspect.signature(getattr(cls, method_name)).parameters
            assert ACTION_PARAM_KEYS[action] in params, f"{name}.{method_name} lacks '{ACTION_PARAM_KEYS[action]}'"
            for extra in ACTION_EXTRA_PARAMS.get(action, ()):
                assert extra in params, f"{name}.{method_name} lacks '{extra}'"
            # every other parameter must be optional, or the platform cannot call it
            for pname, p in params.items():
                if pname not in ("self", ACTION_PARAM_KEYS[action], *ACTION_EXTRA_PARAMS.get(action, ())):
                    assert p.default is not inspect.Parameter.empty, f"{name}.{method_name}: '{pname}' has no default"


def test_graph_client_has_the_mixed_in_abilities():
    assert MicrosoftGraphClient.actions["purge_email"] == "purge_email"
    assert callable(MicrosoftGraphClient.describe_user) and callable(MicrosoftGraphClient.purge_email)
