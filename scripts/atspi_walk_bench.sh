#!/usr/bin/env bash
# AT-SPI2 snapshot walk benchmark + equivalence + freshness checks against real Chromium.
# Not run in CI. Runs inside the `waybound` container image (Chromium, Xvfb, AT-SPI2):
#
#   # 1. Build the ignored live test binary (in a Rust builder container or on Linux):
#   cargo test --release -p waybound-driver-linux --test atspi_walk_live --no-run
#   # 2. Inside the waybound image, under its entrypoint (D-Bus session + AT-SPI2 bus):
#   scripts/atspi_walk_bench.sh target/release/deps/atspi_walk_live-<hash> [runs]
#
# Each page is opened in a fresh Chromium. `atspi_walk_bench` prints one `WB_BENCH {json}`
# line per page with sequential vs pipelined median / p95 latency and fails if any
# pipelined snapshot differs from the sequential one; `atspi_walk_tracks_live_page` prints
# `WB_FRESH {json}` after a DOM rewrite and a navigation. Extra knobs: WB_ATSPI_WINDOWS
# (comma-separated pipeline windows), WB_PAGES (space-separated page names).
set -euo pipefail

BIN=${1:?usage: atspi_walk_bench.sh <atspi_walk_live test binary> [runs]}
RUNS=${2:-30}
PORT=${WB_PORT:-8765}
WORK=$(mktemp -d)
CHROME=$(command -v chromium || command -v google-chrome || command -v google-chrome-stable)

cleanup() {
  pkill -f "user-data-dir=$WORK/profile" 2>/dev/null || true
  sleep 1
  [[ -n "${HTTP_PID:-}" ]] && kill "$HTTP_PID" 2>/dev/null || true
  [[ -n "${XVFB_PID:-}" ]] && kill "$XVFB_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

python3 - "$WORK" <<'PY'
import pathlib
import sys

out = pathlib.Path(sys.argv[1])


def page(name: str, title: str, body: str, script: str = "") -> None:
    html = (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{title}</title>'
        f"</head><body>{body}<script>{script}</script></body></html>"
    )
    (out / name).write_text(html)


page("small.html", "Small", """<h1>Small Page</h1><p>Intro paragraph text.</p>
<button>Save</button><button disabled>Disabled</button>
<input aria-label="Search" value="hello"><input type="checkbox" aria-label="Agree" checked>
<input type="checkbox" aria-label="Opt"><a href="/b.html">Go B</a>
<a href="https://example.invalid/x">External</a>
<details><summary>More</summary><p>Hidden</p></details>
<select aria-label="Pick"><option>One</option><option>Two</option></select>
<ul><li>Alpha</li><li>Beta</li><li>Gamma</li></ul>""")


def big(rows: int) -> str:
    items = []
    for i in range(rows):
        kind = i % 4
        if kind == 0:
            items.append(f'<li><a href="/item/{i}">Item {i}</a></li>')
        elif kind == 1:
            checked = "checked" if i % 3 == 0 else ""
            items.append(f'<li><label><input type="checkbox" {checked}> Check {i}</label></li>')
        elif kind == 2:
            items.append(f"<li><button>Btn {i}</button></li>")
        else:
            items.append(f"<li>Text {i}</li>")
    return "<h1>Big</h1><ul>" + "".join(items) + "</ul>"


page("big1k.html", "Big 1k", big(330))
page("big5k.html", "Big 5k", big(1650))
page("iframes.html", "Frames", '<h1>Frames</h1><a href="/small.html">top link</a>'
     '<iframe src="/small.html" width="600" height="300"></iframe>'
     '<iframe srcdoc="<button>InFrame</button><a href=/x>frame link</a>" width="300" height="100">'
     "</iframe>")
page("mutate.html", "Mutate", '<h1 id="h">gen 0</h1><ul id="u"></ul>', """
let g = 0; const u = document.getElementById('u');
setInterval(() => { g++; document.getElementById('h').textContent = 'gen ' + g;
  u.innerHTML = ''; for (let i = 0; i < 200; i++) { const li = document.createElement('li');
  li.textContent = 'g' + g + ' row ' + i; u.appendChild(li); } }, 3);""")
page("phase.html", "Phase", '<h1 id="h">BEFORE</h1><ul id="u"></ul>', """
const u = document.getElementById('u');
for (let i = 0; i < 300; i++) { const li = document.createElement('li');
  const b = document.createElement('button'); b.textContent = 'before ' + i;
  li.appendChild(b); u.appendChild(li); }
setTimeout(() => { document.getElementById('h').textContent = 'AFTER'; u.innerHTML = '';
  for (let i = 0; i < 300; i++) { const li = document.createElement('li');
    const a = document.createElement('a'); a.href = '/after/' + i; a.textContent = 'after ' + i;
    li.appendChild(a); u.appendChild(li); } }, 6000);""")
page("nav.html", "NavA", "<h1>NAV PAGE A</h1>" + "".join(f"<p>a para {i}</p>" for i in range(100)),
     "setTimeout(() => { location.href = '/navb.html'; }, 6000);")
page("navb.html", "NavB", "<h1>NAV PAGE B</h1>"
     + "".join(f"<button>b button {i}</button>" for i in range(50)))
page("b.html", "B", "<h1>B</h1>")
PY

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK" >/dev/null 2>&1 &
HTTP_PID=$!
if [[ -z "${DISPLAY:-}" ]]; then
  Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
  XVFB_PID=$!
  export DISPLAY=:99
fi
sleep 1

open_page() {
  pkill -f "user-data-dir=$WORK/profile" 2>/dev/null || true
  sleep 0.5
  "$CHROME" --force-renderer-accessibility --no-first-run --no-default-browser-check \
    --user-data-dir="$WORK/profile" --window-size=1280,800 \
    "http://127.0.0.1:$PORT/$1" >/dev/null 2>&1 &
  sleep "$2"
}

failures=0
for page_name in ${WB_PAGES:-small big1k big5k iframes mutate}; do
  open_page "$page_name.html" 6
  equal=1
  [[ "$page_name" == mutate ]] && equal=0
  WB_ATSPI_LABEL=$page_name WB_ATSPI_RUNS=$RUNS WB_ATSPI_EXPECT_EQUAL=$equal \
    "$BIN" --ignored --exact atspi_walk_bench --nocapture 2>&1 | grep -E "WB_BENCH|panicked|differs|test result" || failures=$((failures + 1))
done

open_page phase.html 2.5
WB_ATSPI_EXPECT="after 0" WB_ATSPI_FORBID="before 0" \
  "$BIN" --ignored --exact atspi_walk_tracks_live_page --nocapture 2>&1 | grep -E "WB_FRESH|panicked|stale|test result" || failures=$((failures + 1))

open_page nav.html 2.5
WB_ATSPI_EXPECT="NAV PAGE B" WB_ATSPI_FORBID="NAV PAGE A" WB_ATSPI_EXPECT_URL="/navb.html" \
  "$BIN" --ignored --exact atspi_walk_tracks_live_page --nocapture 2>&1 | grep -E "WB_FRESH|panicked|stale|test result" || failures=$((failures + 1))

echo "atspi_walk_bench: $failures failing run(s)"
exit "$((failures > 0))"
