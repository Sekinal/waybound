"""The upstream proxy URL (with credentials) must never reach the daemon's argv."""

from __future__ import annotations

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
