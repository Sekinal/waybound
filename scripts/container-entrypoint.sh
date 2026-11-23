#!/usr/bin/env bash
set -euo pipefail

# Start an isolated D-Bus session + AT-SPI2 accessibility bus (and openbox when DISPLAY is set)
# so stock Chrome/Chromium exposes its live accessibility tree and handles top-level accelerators
# (Ctrl+L, page.goto()) inside headless Xvfb containers.
exec dbus-run-session -- bash -c '
  if [ -n "${DISPLAY:-}" ] && command -v openbox >/dev/null 2>&1; then
    openbox >/dev/null 2>&1 &
  fi
  if [ -x /usr/libexec/at-spi-bus-launcher ]; then
    /usr/libexec/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
  elif [ -x /usr/lib/at-spi2-core/at-spi-bus-launcher ]; then
    /usr/lib/at-spi2-core/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
  fi
  sleep 0.2
  exec "$@"
' -- "$@"
