"""Unit tests for the waybound MCP stdio JSON-RPC server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from waybound import LaunchOptions, launch
from waybound.mcp_server import _parse_role, handle_rpc_message

if TYPE_CHECKING:
    from waybound.client import Page

REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_BIN = REPO_ROOT / "target" / "debug" / "waybound-daemon"


def test_mcp_server_initialize_list_and_tool_calls() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        provider = lambda: page  # noqa: E731

        # Notifications (no "id") must return None per JSON-RPC 2.0.
        assert (
            handle_rpc_message(provider, {"jsonrpc": "2.0", "method": "notifications/cancelled"})
            is None
        )

        ping_resp = handle_rpc_message(provider, {"jsonrpc": "2.0", "id": 0, "method": "ping"})
        assert ping_resp == {"jsonrpc": "2.0", "id": 0, "result": {}}

        init_resp = handle_rpc_message(
            provider, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
        )
        assert init_resp is not None
        assert init_resp["id"] == 1

        list_resp = handle_rpc_message(
            provider, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        )
        assert list_resp is not None
        result = list_resp["result"]
        assert isinstance(result, dict)
        tools = result["tools"]
        assert isinstance(tools, list)
        assert len(tools) == 8

        url_resp = handle_rpc_message(
            provider,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "waybound_url", "arguments": {}},
            },
        )
        assert url_resp is not None
        url_res = url_resp["result"]
        assert isinstance(url_res, dict)
        content = url_res["content"]
        assert isinstance(content, list)
        assert content[0]["text"] == "https://mock.waybound.local/"

        snap_resp = handle_rpc_message(
            provider,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "waybound_snapshot", "arguments": {}},
            },
        )
        assert snap_resp is not None
        snap_res = snap_resp["result"]
        assert isinstance(snap_res, dict)
        snap_content = snap_res["content"]
        assert isinstance(snap_content, list)
        nodes = json.loads(snap_content[0]["text"])
        assert len(nodes) == 5
        by_id = {node["id"]: node for node in nodes}
        assert by_id["chk-insurance"]["checked"] is True
        assert by_id["chk-insurance"]["disabled"] is True
        assert by_id["combo-cabin"]["expanded"] is False
        assert by_id["btn-search"]["checked"] is None

        shot_resp = handle_rpc_message(
            provider,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "waybound_screenshot", "arguments": {}},
            },
        )
        assert shot_resp is not None
        shot_res = shot_resp["result"]
        assert isinstance(shot_res, dict)
        shot_content = shot_res["content"]
        assert isinstance(shot_content, list)
        assert shot_content[0]["type"] == "image"
        assert shot_content[0]["mimeType"] == "image/png"


def _failing_provider() -> Page:
    msg = "waybound-daemon binary not found"
    raise FileNotFoundError(msg)


def test_launch_failure_is_reported_as_tool_error() -> None:
    resp = handle_rpc_message(
        _failing_provider,
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "waybound_url", "arguments": {}},
        },
    )
    assert resp is not None
    assert "error" not in resp
    result = resp["result"]
    assert isinstance(result, dict)
    assert result["isError"] is True
    content = result["content"]
    assert isinstance(content, list)
    assert "waybound-daemon binary not found" in content[0]["text"]


def test_non_tool_methods_never_launch_the_browser() -> None:
    for request_id, method in enumerate(("initialize", "tools/list", "ping")):
        resp = handle_rpc_message(
            _failing_provider, {"jsonrpc": "2.0", "id": request_id, "method": method}
        )
        assert resp is not None
        assert "result" in resp


def test_client_responses_are_not_answered() -> None:
    assert handle_rpc_message(_failing_provider, {"jsonrpc": "2.0", "id": 3, "result": {}}) is None


def test_unknown_role_is_rejected() -> None:
    assert _parse_role(None) is None
    assert _parse_role("button") is not None
    with pytest.raises(ValueError, match="unknown role 'buton'"):
        _parse_role("buton")
