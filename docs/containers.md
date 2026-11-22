# Running `waybound` in Headless Containers (Podman & Docker)

`waybound` ships a standard OCI [`Containerfile`](../Containerfile) and [`compose.yaml`](../compose.yaml) that run unmodified Linux Chrome/Chromium inside a headless `Xvfb` + `AT-SPI2` + `xdotool` session — completely out-of-band, with zero CDP and without touching your host cursor or keyboard.

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

## Optional: Passive TLS Capture (`tshark` + `SSLKEYLOGFILE`)

Add `--cap-add=NET_RAW --cap-add=NET_ADMIN` when running if you want passive `tshark` decryption inside the container:

```bash
podman run --rm \
  --shm-size=2g \
  --security-opt seccomp=unconfined \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  waybound:latest \
  python3 your_script.py
```

## Scaling Workers with Compose

```bash
podman compose up --build
# or:
docker compose up --build
```
