# syntax=docker/dockerfile:1
# Standard OCI Containerfile — works identically with Podman and Docker:
#   podman build -f Containerfile -t waybound:latest .
#   docker build -f Containerfile -t waybound:latest .

FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    libclang-dev \
    perl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin waybound-daemon

FROM debian:trixie-slim AS runtime
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive \
    ACCESSIBILITY_ENABLED=1 \
    GTK_MODULES=gail:atk-bridge \
    QT_ACCESSIBILITY=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    at-spi2-core \
    ca-certificates \
    curl \
    dbus-x11 \
    fonts-liberation \
    gir1.2-atspi-2.0 \
    gnupg \
    python3 \
    python3-gi \
    python3-pip \
    python3-venv \
    scrot \
    tshark \
    xclip \
    xdotool \
    xvfb \
    && if [ "${TARGETARCH}" = "amd64" ]; then \
        curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
            | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg && \
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
            > /etc/apt/sources.list.d/google-chrome.list && \
        apt-get update && \
        apt-get install -y --no-install-recommends google-chrome-stable; \
    else \
        apt-get install -y --no-install-recommends chromium; \
    fi \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/waybound-daemon /usr/local/bin/waybound-daemon
COPY python /opt/waybound/python
COPY scripts/container-entrypoint.sh /usr/local/bin/waybound-entrypoint

RUN chmod 0755 /usr/local/bin/waybound-daemon /usr/local/bin/waybound-entrypoint \
    && (setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap || true) \
    && pip3 install --no-cache-dir --break-system-packages /opt/waybound/python \
    && useradd -m -s /bin/bash waybound

USER waybound
WORKDIR /home/waybound
ENTRYPOINT ["/usr/local/bin/waybound-entrypoint"]
CMD ["waybound", "doctor"]
