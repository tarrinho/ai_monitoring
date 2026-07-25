#!/usr/bin/env python3
"""Regenerate every README dashboard screenshot (dark + light) from the local demo
server — never from a real deployment. All screenshots in docs/img/dash-*.png MUST
come from this script: the demo server (demo_seed.py) serves synthetic data only, so
no real key names, users, or spend numbers can end up committed to the repo.

  python3 scripts/shoot_screenshots.py                # regenerate all 16 images
  python3 scripts/shoot_screenshots.py --pages spend settings
  python3 scripts/shoot_screenshots.py --themes dark

Requires playwright (`pip install playwright`) and a system chromium (or run
`playwright install chromium` and drop --chromium-path). Not part of the automated
test/build pipeline — a manual maintainer tool, run whenever a dashboard's layout
changes enough that the README screenshots go stale.
"""
import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "docs" / "img"
DEFAULT_PORT = 19926
TOKEN = "demo"
ADMIN_USER = "demo-admin"
ADMIN_PASSWORD = "DemoPass!2026x"  # throwaway — this server never leaves localhost

# (url path, filename stem, needs an authenticated admin session)
PAGES = [
    ("", "ov", False),
    ("spend", "spend", False),
    ("settings", "settings", True),
    ("litellm", "litellm", False),
    ("llamacpp", "llamacpp", False),
    ("gpu", "gpu", False),
    ("ollama", "ollama", False),
    ("alerts", "alerts", True),
]


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def find_free_port(start):
    """demo_seed's port is a plain constant, shared by every session on this box that
    runs this script — a stale/foreign process already bound to it silently serves
    screenshots of THAT server instead (observed live: an unrelated container answered
    on :19926, and every 'successful' screenshot was actually its generic login page,
    not our synthetic data). Scan forward instead of trusting the default is free."""
    for port in range(start, start + 20):
        if port_free(port):
            return port
    raise RuntimeError(f"no free port found in [{start}, {start + 20})")


def wait_for_server(proc, base, timeout=15):
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("demo server exited early — check its stderr above")
        try:
            urllib.request.urlopen(f"{base}/healthz", timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise TimeoutError("demo server never came up")


def verify_own_server(base):
    """A free-port check at start time doesn't rule out a DIFFERENT process grabbing
    the port between the check and our bind, or (as observed live) our own bind
    silently losing a race to an unrelated container's port-forward. Confirm the demo
    admin login this run just seeded actually works before trusting anything it serves."""
    import urllib.error
    import urllib.request
    data = f"username={ADMIN_USER}&password={ADMIN_PASSWORD}".encode()
    req = urllib.request.Request(f"{base}/login", data=data, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        resp = e
    if resp.status not in (200, 302):
        raise RuntimeError(
            f"login check got HTTP {resp.status} from {base} — this isn't our demo "
            "server (a foreign process likely already owns this port)")


def shoot(pg, base, path, theme, needs_admin, out_path):
    q = "" if needs_admin else f"&token={TOKEN}"
    pg.goto(f"{base}/{path}?theme={theme}{q}", wait_until="load", timeout=30000)
    time.sleep(2.5)  # the app polls every 5s continuously — let charts settle, don't wait for idle
    h = pg.evaluate("document.body.scrollHeight")
    pg.set_viewport_size({"width": 1600, "height": min(h + 20, 12000)})
    time.sleep(0.5)
    pg.screenshot(path=str(out_path), timeout=30000)
    print(f"  saved {out_path.name} ({h}px)")


def login(pg, base):
    pg.goto(f"{base}/login", wait_until="load", timeout=30000)
    pg.fill('input[name="username"]', ADMIN_USER)
    pg.fill('input[name="password"]', ADMIN_PASSWORD)
    pg.click('button[type="submit"]')
    pg.wait_for_load_state("load")
    time.sleep(1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pages", nargs="*", default=None,
                     help="page stems to shoot (default: all 8)")
    ap.add_argument("--themes", nargs="*", default=["dark", "light"], choices=["dark", "light"])
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                     help="preferred port; scans forward if it's already taken")
    ap.add_argument("--chromium-path", default="/usr/bin/chromium",
                     help="system chromium binary (skip playwright's own browser download)")
    args = ap.parse_args()

    pages = [p for p in PAGES if args.pages is None or p[1] in args.pages]
    if not pages:
        sys.exit(f"no matching pages in {args.pages!r}")

    from playwright.sync_api import sync_playwright

    port = find_free_port(args.port)
    base = f"http://127.0.0.1:{port}"
    db_path = f"/tmp/screenshot-demo-{port}.db"
    env = dict(os.environ)
    env["MONITOR_PORT"] = str(port)
    env["MONITOR_DB_PATH"] = db_path
    env["MONITOR_ADMIN_USER"] = ADMIN_USER
    env["MONITOR_ADMIN_PASSWORD"] = ADMIN_PASSWORD
    for f in (db_path, "/tmp/demo-gpu.csv"):
        Path(f).unlink(missing_ok=True)

    print(f"starting demo server on :{port} ...")
    proc = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "demo_seed.py")],
                             cwd=str(ROOT), env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        wait_for_server(proc, base)
        verify_own_server(base)
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=args.chromium_path, args=["--no-sandbox"])
            pg = browser.new_page(viewport={"width": 1600, "height": 1000})
            logged_in = False
            for path, stem, needs_admin in pages:
                if needs_admin and not logged_in:
                    login(pg, base)
                    logged_in = True
                for theme in args.themes:
                    out = OUT_DIR / f"dash-{stem}-{theme}.png"
                    shoot(pg, base, path, theme, needs_admin, out)
            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        for f in (db_path, "/tmp/demo-gpu.csv"):
            Path(f).unlink(missing_ok=True)
    print("done.")


if __name__ == "__main__":
    main()
