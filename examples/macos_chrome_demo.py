"""Example: launch unmodified official Google Chrome on macOS via waybound.

Prerequisites:
    1. Build the daemon: `cargo build --workspace`
    2. Grant Accessibility permission to your terminal app in:
       System Settings > Privacy & Security > Accessibility
    3. Run: `cd python && uv run python ../examples/macos_chrome_demo.py`
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from waybound import LaunchOptions, Role, launch


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="waybound-profile-") as profile_dir:
        keylog = Path(profile_dir) / "sslkeys.log"
        with launch(
            LaunchOptions(
                backend="macos",
                launch_chrome=True,
                url="https://www.wikipedia.org",
                profile_dir=Path(profile_dir),
                ssl_keylog=keylog,
            )
        ) as page:
            link = page.get_by_role(Role.LINK, name="English").wait_for(timeout_ms=10_000)
            print(f"Located live DOM link: {link.name!r} at {link.bounds.center}")
            print(
                f"SSLKEYLOGFILE populated: {keylog.exists()} "
                f"({keylog.stat().st_size if keylog.exists() else 0} bytes)"
            )

            # Smooth minimum-jerk pointer movement + native CGEvent click:
            page.get_by_role(Role.LINK, name="English").click()
            search = page.get_by_role(Role.TEXTBOX, name="Search Wikipedia").wait_for(
                timeout_ms=10_000
            )
            print(f"Navigated! Found search box: {search.name!r} at {search.bounds.center}")


if __name__ == "__main__":
    main()
