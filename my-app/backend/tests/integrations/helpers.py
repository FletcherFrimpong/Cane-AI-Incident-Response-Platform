"""Helpers for connector contract tests: run a connector against a fake HTTP layer
and inspect exactly what it sent."""

import json
from typing import Callable

import httpx


class Recorder:
    """Fake HTTP transport. Give it a handler `(request) -> httpx.Response`; every
    request the connector makes is kept in `.requests` for assertions.

        rec = Recorder(lambda req: httpx.Response(200, json={"ok": True}))
        client = MyClient(credentials={...}, config={...})
        rec.attach(client)
        await client.block_ip(ip_address="203.0.113.7")
        assert rec.last.method == "POST" and rec.last.url.path == "/indicators"
        assert rec.json(rec.last)["indicatorValue"] == "203.0.113.7"
    """

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]):
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    def attach(self, client) -> None:
        """Make `client.get_http_client()` return a client wired to this recorder."""
        client._http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(self._handle),
            headers={"Content-Type": "application/json"},
        )

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]

    @staticmethod
    def json(request: httpx.Request):
        return json.loads(request.content.decode() or "null")

    def paths(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.requests]
