"""The upstream proxy URL (with credentials) must never reach the daemon's argv."""

from __future__ import annotations

from dataclasses import replace

import pytest

from waybound.session import LaunchOptions, Session, _daemon_env

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


def test_block_presets_emit_repeatable_cli_flags_and_reject_unknown() -> None:
    opts = LaunchOptions(
        backend="mock",
        block_hosts=("tracker.example",),
        block_presets=("analytics", " ADS "),
        daemon_binary="/nonexistent/waybound-daemon",
    )
    session = Session(opts)
    cmd = session._build_daemon_cmd(socket_path=None, tcp_addr=("127.0.0.1", 1))
    assert "--block-hosts" in cmd
    idx_hosts = cmd.index("--block-hosts")
    assert cmd[idx_hosts + 1] == "tracker.example"

    preset_pairs = [cmd[i + 1] for i, flag in enumerate(cmd) if flag == "--block-preset"]
    assert preset_pairs == ["analytics", "ads"]

    with pytest.raises(ValueError, match="unknown block preset"):
        LaunchOptions(block_presets=("analytics", "bogus"))


def test_headless_wayland_emits_cli_flag_and_rejects_xvfb_combination() -> None:
    opts = LaunchOptions(
        backend="linux",
        headless_wayland=True,
        daemon_binary="/nonexistent/waybound-daemon",
    )
    session = Session(opts)
    cmd = session._build_daemon_cmd(socket_path=None, tcp_addr=("127.0.0.1", 1))
    assert "--headless-wayland" in cmd
    assert "--headless-xvfb" not in cmd

    with pytest.raises(ValueError, match="mutually exclusive"):
        LaunchOptions(backend="linux", headless_xvfb=True, headless_wayland=True)


def test_attach_with_keylog_and_proxy_is_rejected() -> None:
    attach = LaunchOptions(
        backend="macos",
        pid=4242,
        ssl_keylog="/nonexistent/keys.log",
        proxy=UPSTREAM_URL,
        daemon_binary="/nonexistent/waybound-daemon",
    )
    with pytest.raises(ValueError, match="launch_chrome"):
        Session(attach)
    # Launching (in-process tap) or attaching without a proxy is fine.
    Session(replace(attach, launch_chrome=True, pid=None))
    Session(replace(attach, proxy=None))
