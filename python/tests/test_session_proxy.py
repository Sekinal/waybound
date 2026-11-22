"""The upstream proxy URL (with credentials) must never reach the daemon's argv."""

from __future__ import annotations

from typing import TYPE_CHECKING

from waybound.session import LaunchOptions, Session, _daemon_env

if TYPE_CHECKING:
    import pytest

UPSTREAM_URL = "http://user:s3cret@proxy.example.com:8080"


def test_proxy_is_passed_in_env_not_argv() -> None:
    opts = LaunchOptions(
        backend="linux",
        launch_chrome=True,
        proxy=UPSTREAM_URL,
        daemon_binary="/nonexistent/waybound-daemon",
    )
    session = Session(opts)
    cmd = session._build_daemon_cmd(socket_path=None, tcp_addr=("127.0.0.1", 1))
    assert not any("s3cret" in arg or "proxy.example.com" in arg for arg in cmd)
    assert "--proxy" not in cmd
    assert _daemon_env(UPSTREAM_URL)["WAYBOUND_PROXY"] == UPSTREAM_URL


def test_inherited_proxy_env_passes_through_when_no_proxy_option(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An inherited WAYBOUND_PROXY is deliberately forwarded (environment-based configuration,
    # as used by `waybound-mcp`); an explicit `proxy` option overrides it.
    monkeypatch.setenv("WAYBOUND_PROXY", UPSTREAM_URL)
    assert _daemon_env(None)["WAYBOUND_PROXY"] == UPSTREAM_URL
    override = "socks5://other:pw@proxy2.example.com:1080"
    assert _daemon_env(override)["WAYBOUND_PROXY"] == override
    monkeypatch.delenv("WAYBOUND_PROXY")
    assert "WAYBOUND_PROXY" not in _daemon_env(None)
