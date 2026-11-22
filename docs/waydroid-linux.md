# Running `waybound` with Waydroid on Linux (ARM64 / x86_64)

The `android` backend drives Chrome on any Android device or emulator reachable over ADB. Connecting to an already-running Waydroid (or other Android device) by ADB serial is the supported path.

> **Status: `launch_waydroid=True` is experimental and does not work as written** ([#16](https://github.com/Sekinal/waybound/issues/16)). The daemon waits for ADB on `127.0.0.1:<adb_port>`, but nothing forwards Waydroid's `adbd` to that address; the Python SDK's default `startup_timeout_s` (5 s) is shorter than the daemon's 30 s ADB wait; Waydroid runs a single system-wide container, so `instance_id` does not give separate instances and stopping one session stops them all; and the Android `http_proxy` is set to `127.0.0.1`, which inside the container is the container itself. This path is not exercised in CI.

## Prerequisites (Ubuntu / Debian Linux Host)

1. **Kernel binder support** (standard on modern Ubuntu/Debian ARM64 & x86_64 kernels):
   ```bash
   sudo modprobe binder_linux devices="binder,hwbinder,vndbinder"
   ```
2. **Install Waydroid and ADB:**
   ```bash
   sudo apt-get update
   sudo apt-get install -y waydroid android-tools-adb
   sudo waydroid init -s GAPPS
   ```
   `weston` is only needed for the experimental `launch_waydroid=True` path.
3. **Install official Google Chrome APK inside Waydroid:**
   ```bash
   waydroid app install /path/to/GoogleChrome.apk
   ```

## Usage from Python

Connect to a running Waydroid / Android device by ADB serial (any serial that `adb devices` lists once you have run `adb connect`):

```python
from waybound import LaunchOptions, Role, launch

with launch(LaunchOptions(backend="android", serial="<device-ip>:5555")) as page:
    page.goto("https://www.wikipedia.org")
    link = page.get_by_role(Role.LINK, name="English")
    link.wait_for()
    link.click()
    print("URL:", page.url())
    png = page.screenshot()
```

## Limitations of the `android` backend

- Input goes through `adb shell input`, which cannot send modifier chords: modifiers are dropped, and `fill()` appends to the field instead of replacing its content.
- Pointer motion is not simulated; taps land directly on the target.
- Accessibility snapshots come from `uiautomator dump` and are capped at 2,000 nodes.
- Passive response capture (`ssl_keylog`) does not apply: nothing configures a TLS key log inside Android.
