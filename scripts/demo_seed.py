#!/usr/bin/env python3
"""Throwaway demo server — serves the real dashboards backed by synthetic data so
we can screenshot full panels for the README. No real backends, no secrets.

  MONITOR_DB_PATH=/tmp/demo.db python3 scripts/demo_seed.py   # serves :19926
"""
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("MONITOR_DASHBOARD_TOKEN", "demo")
os.environ.setdefault("MONITOR_PORT", "19926")
os.environ.setdefault("MONITOR_DB_PATH", "/tmp/demo.db")
# non-empty backend URLs so /api/nav shows every dashboard link
os.environ.setdefault("LITELLM_BASE_URL", "http://demo:4000")
os.environ.setdefault("LITELLM_MASTER_KEY", "sk-demo")
os.environ.setdefault("OLLAMA_BASE_URL", "http://demo:11434")
os.environ.setdefault("LLAMACPP_BASE_URL", "http://demo:8080")
os.environ.setdefault("GPU_METRICS_FILE", "/tmp/demo-gpu.csv")

import config  # noqa: E402
import db  # noqa: E402
import app as A  # noqa: E402
from aiohttp import web  # noqa: E402

MODELS = ["glm-4.7-flash", "llama-cpp/Qwen3-Coder-Next", "ollama/Qwen3-Coder-Next", "gpt-oss:20b"]


def wave(ts, base, amp, period, phase=0.0):
    return base + amp * math.sin(ts / period + phase)


def make_snap(ts):
    cpu = max(2, wave(ts, 42, 30, 300))
    mem = max(20, wave(ts, 63, 12, 900, 1))
    util = max(0, min(100, wave(ts, 78, 22, 240, 2)))
    pps = max(0, wave(ts, 52, 14, 180, 0.5))
    kv = max(0, min(100, wave(ts, 46, 30, 210, 1.5)))
    active = int(max(0, min(4, round(wave(ts, 2, 2, 160)))))
    wait = max(20, wave(ts, 140, 90, 200, 2))
    req = max(0.2, wave(ts, 7.5, 5, 260, 1))
    return {"ts": ts, "collectors": {
        "host": {"available": True, "cpu_pct": round(cpu, 1), "mem_pct": round(mem, 1),
                 "mem_used": int(mem / 100 * 128) * 2**30, "mem_total": 128 * 2**30,
                 "mem_avail": int((100 - mem) / 100 * 128) * 2**30,
                 "disk": {"pct": 61.4, "used": 880 * 2**30, "total": 1400 * 2**30},
                 "load": [round(cpu / 8, 2), round(cpu / 9, 2), round(cpu / 11, 2)], "ncpu": 20,
                 "info": {"kernel": "6.11.0-1004-nvidia", "arch": "aarch64",
                          "hostname": "dgx-spark", "cpu_model": "NVIDIA Grace (Arm Neoverse)",
                          "cpu_cores": 20, "cpu_threads": 20, "cpu_mhz": 3400,
                          "swap_total": 8 * 2**30}},
        "procs": {"available": True, "ncpu": 20,
                  "top_cpu": [{"app": n, "cpu": round(c, 1), "pid": 1000 + i, "ram": r * 2**30}
                              for i, (n, c, r) in enumerate([
                                  ("llama-server", wave(ts, 620, 180, 200), 53),
                                  ("ollama", wave(ts, 210, 90, 240, 1), 18),
                                  ("python(litellm)", wave(ts, 46, 20, 300), 2),
                                  ("postgres", wave(ts, 12, 6, 260), 1),
                                  ("ai-monitoring", wave(ts, 3, 1, 300), 1)])],
                  "top_ram": [{"app": n, "ram": r * 2**30, "pid": 1000 + i, "cpu": 1.0}
                              for i, (n, r) in enumerate([
                                  ("llama-server", 53), ("ollama", 18), ("postgres", 3),
                                  ("timescaledb", 2), ("crowdsec", 1)])]},
        "gpu": {"available": True, "count": 1, "vendor": "nvidia", "mode": "file",
                "util": round(util, 1), "vram_used": int(72 * 2**30), "vram_total": int(120 * 2**30),
                "power": round(wave(ts, 210, 60, 220), 0), "temp_max": round(wave(ts, 61, 8, 400), 0),
                "throttled": False, "target": "local",
                "gpus": [{"name": "NVIDIA GB10", "util": round(util, 1), "vram_used": int(72 * 2**30),
                          "vram_total": int(120 * 2**30), "temp": 61, "power": 210}]},
        "ollama": {"available": True, "version": "0.30.11", "models_running": 2,
                   "models_installed": 23, "ram_used": int(53 * 2**30), "vram_used": int(49 * 2**30),
                   "gpu_pct": 92.0,
                   "models": [
                       {"name": "Qwen3-Coder-Next:latest", "size": int(53 * 2**30),
                        "size_vram": int(49 * 2**30), "gpu_pct": 92, "params": "30.5B",
                        "quant": "Q4_K_XL", "family": "qwen3", "expires_at": None},
                       {"name": "nomic-embed-text:latest", "size": int(0.3 * 2**30),
                        "size_vram": int(0.3 * 2**30), "gpu_pct": 100, "params": "137M",
                        "quant": "F16", "family": "nomic-bert", "expires_at": None}]},
        "llamacpp": {"available": True, "status": "ok",
                     "model": "/models/Qwen3-Coder-Next-UD-Q4_K_XL.gguf", "ctx_size": 262144,
                     "n_slots": 4, "slots_active": active, "slots_busy_pct": round(active / 4 * 100, 1),
                     "kv_cache_pct": round(kv, 1), "predicted_per_second": round(pps, 1)},
        "litellm": {"available": True, "healthy": 4, "unhealthy": 0, "models": MODELS,
                    "spend_mode": "full", "backlog": active,
                    "requests_window": int(wave(ts, 460, 120, 400)), "tokens_today": 40312063,
                    "wait_avg_ms": round(wait, 0), "wait_max_ms": round(wait * 2.4, 0),
                    "req_rate": round(req, 2), "tok_in_rate": round(req * 120, 0),
                    "tok_out_rate": round(req * 48, 0), "error_pct": round(max(0, wave(ts, 0.6, 0.8, 300)), 2),
                    "cost_rate_hr": round(wave(ts, 1.9, 0.7, 260), 2), "ttft_avg_ms": round(wait * 0.7, 0),
                    "cache_hit_pct": round(wave(ts, 38, 12, 350), 1), "p50_ms": round(wait, 0),
                    "p95_ms": round(wait * 1.8, 0), "p99_ms": round(wait * 2.3, 0),
                    "per_model": [
                        {"model": "llama-cpp/Qwen3-Coder-Next", "reqs": 461, "tokens": 46571486,
                         "wait_avg_ms": round(wait, 0), "wait_max_ms": round(wait * 2, 0),
                         "p95_ms": round(wait * 1.8, 0), "slo_pct": 98.4, "cost": 0.0},
                        {"model": "ollama/Qwen3-Coder-Next", "reqs": 120, "tokens": 903214,
                         "wait_avg_ms": round(wait * 1.2, 0), "wait_max_ms": round(wait * 3, 0),
                         "p95_ms": round(wait * 2.1, 0), "slo_pct": 95.1, "cost": 0.0},
                        {"model": "gpt-oss:20b", "reqs": 33, "tokens": 51920,
                         "wait_avg_ms": round(wait * 0.9, 0), "wait_max_ms": round(wait * 1.7, 0),
                         "p95_ms": round(wait * 1.5, 0), "slo_pct": 99.0, "cost": 0.0}],
                    "top_keys": [{"api_key": f"sk-...{k}", "key": f"sk-...{k}",
                                  "alias": a, "key_alias": a, "key_name": a, "reqs": rq,
                                  "total_spend": round(s, 2), "spend": round(s, 2)}
                                 for k, a, s, rq in [
                                     ("a1", "langgraph-agent", 4.82, 214), ("b2", "coder-ide", 3.11, 168),
                                     ("c3", "batch-eval", 2.04, 96), ("d4", "rag-indexer", 1.55, 74),
                                     ("e5", "chat-ui", 0.98, 51), ("f6", "ci-tests", 0.72, 38),
                                     ("g7", "notebook", 0.41, 22), ("h8", "cron-summary", 0.33, 15),
                                     ("i9", "smoke", 0.12, 8), ("j0", "adhoc", 0.05, 3)]]},
        "containers": {"available": True, "containers": [
            {"name": n, "running": r, "uptime_s": u, "down_s": d, "status": s}
            for n, r, u, d, s in [
                ("llama-cpp-server", True, 86400 * 3, None, "running"),
                ("ollama", True, 86400 * 3, None, "running"),
                ("litellm", True, 86400 * 2, None, "running"),
                ("litellm-db", True, 86400 * 2, None, "running"),
                ("ai-monitoring", True, 3600 * 5, None, "running"),
                ("open-webui", True, 86400, None, "running"),
                ("searxng", True, 86400, None, "running"),
                ("old-batch-job", False, None, 7200, "exited")]]},
    }}


def seed_long_history(now):
    """Seed the rollup tiers DIRECTLY so the 30d + 12mo windows showcase a full
    span in the demo. Raw+rollup can't backfill a year (the 1-hour rollup only
    looks back 3 days), so we write the aggregated tiers straight:
      - metrics_1h / key_series_1h / proc_series_1h : hourly, 370 days → 30d + 12mo
      - metrics_1m                                  : 1-minute, 2 days → 24h
    Set DEMO_FAST=1 to skip (2-hour raw only, for quick screenshot runs).
    DEMO_HISTORY_DAYS (default 370) / DEMO_HISTORY_MIN_DAYS (default 2) tune the
    hourly and 1-minute spans."""
    if os.environ.get("DEMO_FAST"):
        return
    hist_days = int(os.environ.get("DEMO_HISTORY_DAYS", "370"))
    min_days = int(os.environ.get("DEMO_HISTORY_MIN_DAYS", "2"))
    cols = db._METRIC_COLS
    ph = ",".join("?" * len(cols))
    ins_1h = f"INSERT OR REPLACE INTO metrics_1h(bucket,{','.join(cols)}) VALUES (?,{ph})"
    ins_1m = f"INSERT OR REPLACE INTO metrics_1m(bucket,{','.join(cols)}) VALUES (?,{ph})"
    with db._connect() as conn:
        for h in range(hist_days * 24):                # hourly
            b = int((now - h * 3600) / 3600) * 3600
            snap = make_snap(b)
            c = snap["collectors"]
            vals = A._metrics_row(snap)
            conn.execute(ins_1h, (b, *[vals.get(col) for col in cols]))
            for k in c["litellm"]["top_keys"]:
                lab = k.get("alias") or k.get("key") or "?"
                rq = k.get("reqs")
                rq = rq if rq is not None else (k.get("cost") or 0)
                conn.execute(
                    "INSERT INTO key_series_1h(bucket,label,reqs) VALUES (?,?,?)",
                    (b, str(lab)[:80], float(rq or 0)))
            for kind, key in (("cpu", "top_cpu"), ("ram", "top_ram")):
                for a in c["procs"][key]:
                    conn.execute(
                        "INSERT INTO proc_series_1h(bucket,kind,app,val) VALUES (?,?,?,?)",
                        (b, kind, str(a.get("app", "?"))[:80], float(a.get(kind) or 0)))
        for m in range(min_days * 24 * 60):            # 1-minute → 24h
            b = int((now - m * 60) / 60) * 60
            vals = A._metrics_row(make_snap(b))
            conn.execute(ins_1m, (b, *[vals.get(col) for col in cols]))


def seed_history():
    db.init()
    now = time.time()
    seed_long_history(now)     # a year of hourly history → 30d + 12mo windows
    # 2h of 1-minute points so every chart shows a full line immediately
    for i in range(120, 0, -1):
        ts = now - i * 60
        snap = make_snap(ts)
        c = snap["collectors"]
        db.insert(ts, c)
        db.insert_metrics(ts, A._metrics_row(snap))
        db.insert_key_series(ts, c["litellm"]["top_keys"])
        db.insert_proc_series(ts, "cpu", c["procs"]["top_cpu"], "cpu")
        db.insert_proc_series(ts, "ram", c["procs"]["top_ram"], "ram")
        A._ring.append(snap)
    A._latest = make_snap(now)
    # a couple of demo alerts/anomalies/events for the Alerts page
    db.record_alert(now - 900, "gpu_util", "GPU", "GPU util 96% ≥ 90%")
    db.record_alert(now - 300, "backlog", "LiteLLM", "backlog 12 ≥ 10")
    db.record_anomaly(now - 600, "langgraph-agent", "spike", "10× baseline req rate")
    db.record_event(now - 1800, "llamacpp", True, "up")


# keep the live loop producing the same synthetic data (don't clobber _latest)
async def _fake_sample(session):
    return make_snap(time.time())


# inject a theme-from-query shim so ?theme=light|dark works for screenshots
_orig_serve = A._serve_page


def _serve_with_theme(path, prefix="", **kw):
    # forward user/role (and any future kwargs) to the real _serve_page so the
    # sidebar user/admin links render — the app now stamps those in server-side.
    resp = _orig_serve(path, prefix, **kw)
    html = resp.text
    if html:
        shim = ("<script>(function(){var p=new URLSearchParams(location.search)"
                ".get('theme');if(p){localStorage.setItem('aimon-theme',p);"
                "document.documentElement.setAttribute('data-theme',p);}})();</script>")
        # ?pop=1 forces the Host hardware popover open (so it can be screenshot)
        shim += ("<style id='_popforce'></style><script>(function(){"
                 "if(new URLSearchParams(location.search).get('pop'))"
                 "document.getElementById('_popforce').textContent="
                 "'.hw-pop{display:block!important;position:static!important;box-shadow:none;margin-top:8px}';"
                 "})();</script>")
        resp.text = html.replace("<head>", "<head>" + shim, 1)
    return resp


if __name__ == "__main__":
    seed_history()
    A._sample_once = _fake_sample
    A._serve_page = _serve_with_theme
    # keep ?token=&theme= in the URL (no cookie-strip redirect) so screenshots
    # can pin the theme and the page JS can read the token from the query.
    A._maybe_cookie_redirect = lambda *a, **k: None
    print(f"demo server on :{config.MONITOR_PORT}  token={config.DASHBOARD_TOKEN}")
    web.run_app(A.build_app(), host="127.0.0.1", port=config.MONITOR_PORT, print=None)
