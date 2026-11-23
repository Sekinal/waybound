# Running `waybound` in Headless Containers (Podman & Docker)

`waybound` ships a standard OCI [`Containerfile`](../Containerfile) and [`compose.yaml`](../compose.yaml) that run unmodified Linux Chrome/Chromium inside a headless `Xvfb` + `AT-SPI2` session — completely out-of-band, with zero CDP and without touching your host cursor or keyboard. Input goes to the Xvfb display through X11 `XTEST`; `xdotool` is installed as a fallback.

Both **Podman** (rootless by default, recommended) and **Docker** are first-class and use identical commands.

## Build

```bash
# Podman (recommended, rootless)
podman build -f Containerfile -t waybound:latest .

# Docker
docker build -f Containerfile -t waybound:latest .
```

> **Architecture note:** On `linux/amd64`, the image installs official **Google Chrome Stable**. On `linux/arm64` (including Apple Silicon `podman machine`), it installs stock Debian **Chromium**.

## Run Diagnostics (`waybound doctor`)

```bash
podman run --rm --shm-size=2g --security-opt seccomp=unconfined waybound:latest
```

## Run a Headless Linux Automation Script

```bash
podman run --rm \
  --shm-size=2g \
  --security-opt seccomp=unconfined \
  waybound:latest \
  python3 -c '
import waybound

opts = waybound.LaunchOptions(
    backend="linux",
    headless_xvfb=True,
    launch_chrome=True,
    url="https://example.com",
)
with waybound.launch(opts) as page:
    heading = page.get_by_role(waybound.Role.HEADING).wait_for(timeout_ms=15_000)
    print("Heading:", heading.name)
'
```

## Optional: Passive TLS Capture (`SSLKEYLOGFILE`)

When the script launches Chrome itself (`launch_chrome=True`) and sets `ssl_keylog=...`, decryption happens inside the daemon on the traffic it relays, so no extra capabilities are needed.

The `tshark` path is only used when attaching to a Chrome the daemon did not launch (`pid=...`). It captures on the `any` interface (override with `--net-iface` / `WAYBOUND_NET_IFACE`), and the daemon exits at startup if `tshark` is missing or cannot open the interface. That needs packet-capture capabilities:

```bash
podman run --rm \
  --shm-size=2g \
  --security-opt seccomp=unconfined \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  waybound:latest \
  python3 your_script.py
```

## Reusing a Logged-In Session

Mount a session bundle read-only and restore it with `waybound profile import` before launching Chrome. Only bundles created by a Linux Chrome using the `basic` password store (`LaunchOptions(password_store="basic")`) decrypt inside the container; see [profile-portability.md](profile-portability.md).

## Debugging Accessibility Snapshots

Snapshots walk Chrome's AT-SPI2 tree with pipelined D-Bus calls. To rule that out when a
snapshot looks wrong, pass `-e WAYBOUND_ATSPI_WALK=sequential` to `podman run` to force the
original one-call-at-a-time walk (slower, same output); `RUST_LOG=waybound_driver_linux=debug`
logs which walk ran. See [ARCHITECTURE.md](../ARCHITECTURE.md#linux-at-spi2-tree-walk).

## Compose

[`compose.yaml`](../compose.yaml) builds the image and runs `waybound doctor` with the capture capabilities added. The entrypoint only starts a D-Bus session and the AT-SPI2 bus; Xvfb is started by the daemon for sessions with `headless_xvfb=True`, always on display `:99`, so run one such session per container.

```bash
podman compose up --build
# or:
docker compose up --build
```
