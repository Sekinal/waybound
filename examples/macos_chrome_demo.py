"""Example: launch unmodified official Google Chrome on macOS via waybound.

Prerequisites:
    1. Build the daemon: `cargo build --workspace`
    2. Grant Accessibility permission to your terminal app in:
       System Settings > Privacy & Security > Accessibility
    3. Run: `cd python && uv run python ../examples/macos_chrome_demo.py`
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from waybound import LaunchOptions, Role, launch


def main() -> None:
    with (
        tempfile.TemporaryDirectory(prefix="waybound-profile-") as profile_dir,
        launch(
            LaunchOptions(
                backend="macos",
                launch_chrome=True,
                url="https://example.com",
                profile_dir=Path(profile_dir),
                ssl_keylog=Path(profile_dir) / "sslkeys.log",
            )
        ) as page,
    ):
        # Give Chrome a moment to open its initial window and render the page.
        time.sleep(2.5)

        nodes = page.snapshot_tree()
        print(f"Captured {len(nodes)} accessibility nodes from live Google Chrome:")
        for node in nodes[:15]:
            print(f"  - [{node.role.value}] name={node.name!r} bounds={node.bounds}")

        # Example semantic interaction: wait for a link on example.com.
        link = page.get_by_role(Role.LINK, name="More information").wait_for(timeout_ms=5_000)
        print(f"Located link: {link.name!r} at {link.bounds.center}")


if __name__ == "__main__":
    main()
