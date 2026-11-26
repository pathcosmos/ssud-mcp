import asyncio

import httpx
import pytest

from ssud_mcp.client import AgentClient, AgentError
from ssud_mcp.server import create_server


def test_browser_pairing_recovers_and_does_not_send_password(tmp_path):
    current = None
    approved = False

    def respond(request):
        nonlocal current
        if request.url.path == "/api/agent/pair":
            current = request.content
            assert b"password" not in current
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/api/agent/exchange":
            if request.content != current:
                return httpx.Response(404)
            if not approved:
                return httpx.Response(202, json={"pending": True})
            return httpx.Response(200, json={"token": "test-only", "expires": 10**10})
        if request.url.path == "/api/browse":
            assert request.headers["Authorization"] == "Bearer test-only"
            return httpx.Response(200, json={"items": []})
        assert request.url.path == "/api/agent/disconnect"
        return httpx.Response(200, json={"ok": True})

    url = "https://files.example.org"
    transport = httpx.Client(base_url=url, transport=httpx.MockTransport(respond))
    client = AgentClient(url, "", "", "", "", tmp_path, pairing=True, http=transport)
    first = client.browser_login()
    assert not first["connected"] and "secret" not in first
    current = None
    second = client.browser_login()
    assert second["connection_code"] != first["connection_code"]
    assert second["approval_url"].endswith("#" + second["connection_code"])
    approved = True
    assert client.browser_login() == {"connected": True}
    assert client.browse() == {"items": []}
    client.close()


def test_default_environment_registers_browser_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("SSUD_AGENT_LOCAL_ROOT", str(tmp_path))
    monkeypatch.setenv("SSUD_AGENT_URL", "https://files.example.org")
    monkeypatch.delenv("SSUD_AGENT_AUTH", raising=False)
    client = AgentClient.from_environment()
    tools = asyncio.run(create_server(client).list_tools())
    assert {"connect_files", "upload_file", "download_file"} <= {tool.name for tool in tools}
    client.close()


def test_remote_http_requires_opt_in(tmp_path, monkeypatch):
    monkeypatch.setenv("SSUD_AGENT_LOCAL_ROOT", str(tmp_path))
    monkeypatch.setenv("SSUD_AGENT_URL", "http://files.example.org")
    monkeypatch.setenv("SSUD_AGENT_AUTH", "browser")
    monkeypatch.delenv("SSUD_AGENT_ALLOW_HTTP", raising=False)
    with pytest.raises(AgentError, match="HTTPS"):
        AgentClient.from_environment()


def test_download_link_result_uses_configured_server_origin(tmp_path):
    url = "https://files.example.org"

    def respond(request):
        if request.url.path == "/api/agent/disconnect":
            return httpx.Response(200, json={"ok": True})
        assert request.url.path == "/api/download-links"
        return httpx.Response(
            200, json={"download_url": "/d/abcDEF0123_-", "download_expires": 123}
        )

    transport = httpx.Client(base_url=url, transport=httpx.MockTransport(respond))
    client = AgentClient(url, "", "", "", "", tmp_path, pairing=True, http=transport)
    client.expires = 10**10
    client.http.headers["Authorization"] = "Bearer test-only"
    assert client.create_download_link("report.txt") == {
        "download_url": url + "/d/abcDEF0123_-",
        "download_expires": 123,
    }
    client.close()
