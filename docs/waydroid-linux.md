# Running `waybound` with Headless Waydroid on Linux (ARM64 / x86_64)

## Prerequisites (Ubuntu / Debian Linux Host)

1. **Kernel binder support** (standard on modern Ubuntu/Debian ARM64 & x86_64 kernels):
   ```bash
   sudo modprobe binder_linux devices="binder,hwbinder,vndbinder"
   ```
2. **Install Waydroid, headless Weston, ADB, and tshark:**
   ```bash
   sudo apt-get update
   sudo apt-get install -y waydroid weston android-tools-adb tshark
   sudo waydroid init -s GAPPS
   ```
3. **Install official Google Chrome APK inside Waydroid:**
   ```bash
   waydroid app install /path/to/GoogleChrome.apk
   ```

## Usage from Python

```python
from waybound import LaunchOptions, Role, launch

with launch(
    LaunchOptions(
        backend="android",
        launch_waydroid=True,
        instance_id="worker-01",
        adb_port=5555,
        url="https://www.wikipedia.org",
        proxy="socks5://user:pass@proxy.example.com:1080",
        timezone="America/New_York",
    )
) as page:
    page.get_by_role(Role.LINK, name="English").wait_for().click()
    print("URL:", page.url())
    png = page.screenshot()
```

Or connect directly to an already-running Waydroid / Android device by ADB serial:

```python
with launch(LaunchOptions(backend="android", serial="127.0.0.1:5555")) as page:
    page.goto("https://www.wikipedia.org")
```
