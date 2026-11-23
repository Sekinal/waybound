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

The `tshark` path is only used when attaching to a Chrome the daemon did not launch (`pid=...`). That needs packet-capture capabilities:

```bash
podman run --rm \
  --shm-size=2g \
  --security-opt seccomp=unconfined \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  waybound:latest \
  python3 your_script.py
```

## Compose

[`compose.yaml`](../compose.yaml) builds the image and runs `waybound doctor` with the capture capabilities added. The entrypoint only starts a D-Bus session and the AT-SPI2 bus; Xvfb is started by the daemon for sessions with `headless_xvfb=True`, on display `:99` unless `display=":N"` selects another number. To run several sessions in one container use `BrowserPool(display_backend="wayland")` (one in-process headless compositor per slot) or `BrowserPool(isolated_displays=True)`, which starts a separate Xvfb (from `:100`), D-Bus session, openbox and AT-SPI2 bus per slot; budget several hundred MB of RAM and enough `--shm-size` per slot.

```bash
podman compose up --build
# or:
docker compose up --build
```
