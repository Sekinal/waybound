"""Example: parallel SPA interaction + zero-MITM passive JSON API capture.

Demonstrates:
    - Launching unmodified official Google Chrome with zero CDP / zero browser fork
    - True parallel `asyncio.gather(page.wait_for_response(...), locator.fill(...))`
    - Behavioral v0.2 stochastic pointer motion, click dwell, and human typing cadence
    - Passive TLS 1.3 + HTTP/2 + gzip/brotli decryption via `SSLKEYLOGFILE` -> `resp.json()`
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from waybound import LaunchOptions, Role, launch_async


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="waybound-spa-") as profile_dir:
        keylog = Path(profile_dir) / "sslkeys.log"
        async with launch_async(
            LaunchOptions(
                backend="macos",
                launch_chrome=True,
                focus=True,
                url="https://en.wikipedia.org/wiki/Main_Page",
                profile_dir=Path(profile_dir),
                ssl_keylog=keylog,
            )
        ) as page:
            search = page.get_by_role(Role.TEXTBOX, name="Search Wikipedia")
            await search.wait_for(timeout_ms=12_000)
            print("Loaded URL:", await page.url())

            resp, _ = await asyncio.gather(
                page.wait_for_response("search/title", timeout_ms=12_000),
                search.fill("Rust programming"),
            )
            print(f"Captured [{resp.status}] {resp.url} ({resp.content_type})")
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("pages"), list):
                titles = [p.get("title") for p in data["pages"][:5] if isinstance(p, dict)]
                print("Top autocomplete JSON titles:", titles)


if __name__ == "__main__":
    asyncio.run(main())
