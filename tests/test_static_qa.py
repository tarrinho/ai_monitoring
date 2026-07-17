# Static QA — source inspection, no network/runtime backends required.
# Enforces the rules.md invariants that apply to this project: env-only
# secrets, dashboard security (§17), version consistency (§0a), fail-fast
# config, and container hardening.
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import config

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web" / "index.html"


# ------------------------------------------------------------- secrets --------
def test_no_hardcoded_secrets_in_source():
    pat = re.compile(
        r'(sk-[A-Za-z0-9]{8})|'
        r'(master_key\s*=\s*["\'][^"\'$]{6})|'
        r'(password\s*=\s*["\'][^"\'$]{4})',
        re.I,
    )
    for p in list(ROOT.glob("*.py")) + list((ROOT / "collectors").glob("*.py")):
        txt = p.read_text(encoding="utf-8")
        assert not pat.search(txt), f"possible hardcoded secret in {p.name}"


def test_env_example_has_only_placeholders():
    txt = (ROOT / ".env.example").read_text(encoding="utf-8")
    # any *_KEY / MASTER_KEY line must be blank or a CHANGE_ME placeholder
    for line in txt.splitlines():
        if re.match(r'^[A-Z_]*(KEY|TOKEN)=', line):
            val = line.split("=", 1)[1].strip()
            assert val == "" or "CHANGE_ME" in val, f"real-looking secret: {line}"


def test_gitignore_blocks_env_and_db():
    txt = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in txt
    assert "*.db" in txt


def test_redacted_summary_never_exposes_key_value(monkeypatch):
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-supersecretvalue")
    s = config.redacted_summary()
    assert s["litellm_key"] == "set"
    assert "supersecret" not in repr(s)


# ---------------------------------------------------- version consistency -----
def test_single_version_constant():
    assert config.VERSION.startswith("AI-Monitoring_")
    # version string must not be duplicated as a literal elsewhere in source
    for p in (ROOT / "app.py", ROOT / "db.py"):
        assert config.VERSION not in p.read_text(encoding="utf-8"), \
            f"version literal duplicated in {p.name}; reference config.VERSION"


# --------------------------------------------------------- fail-fast cfg ------
def test_validate_rejects_bad_port(monkeypatch):
    monkeypatch.setattr(config, "MONITOR_PORT", 0)
    assert any("MONITOR_PORT" in e for e in config.validate())


def test_validate_rejects_fast_interval(monkeypatch):
    monkeypatch.setattr(config, "SAMPLE_INTERVAL", 0.1)
    assert any("INTERVAL" in e for e in config.validate())


def test_validate_requires_key_when_litellm_url_set(monkeypatch):
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://x:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", None)
    assert any("MASTER_KEY" in e for e in config.validate())


# --------------------------------------------------- dashboard security §17 ---
def test_dashboard_has_single_escapehtml():
    html = WEB.read_text(encoding="utf-8")
    assert html.count("function escapeHtml") == 1


def test_dashboard_innerHTML_only_via_sanitizer():
    html = WEB.read_text(encoding="utf-8")
    # the only `innerHTML =` assignment must be the DOMPurify-wrapped setHtml
    assigns = re.findall(r'innerHTML\s*=', html)
    assert len(assigns) == 1
    assert "DOMPurify.sanitize" in html


def test_dashboard_timers_tracked_and_cleared():
    html = WEB.read_text(encoding="utf-8")
    assert "_timers.push(setInterval" in html
    assert "_timers.forEach(clearInterval)" in html
    assert "beforeunload" in html


def test_window_selector_and_series_wiring():
    html = WEB.read_text(encoding="utf-8")
    for w in ("15m", "1h", "24h", "30d", "12mo"):
        assert f'data-w="{w}"' in html, f"missing window button {w}"
    assert "/api/series" in html and "loadSeries" in html
    # long windows must render calendar dates on the axis, not time-of-day only
    assert "toLocaleDateString" in html, "axis not date-aware for 30d/12mo"


def test_axis_labels_adapt_to_data_span_not_window():
    # Bug: a 12mo view holding only a few days of history rendered the SAME
    # "Jul '26" on every tick (label granularity was chosen from the window name,
    # not the data). Fix: axisT(pts) picks granularity from the actual span of the
    # plotted points. Every windowed dashboard must use it and must NOT branch the
    # axis format on the window name (WIN==="12mo"/"30d").
    for name in ("index", "gpu", "ollama", "llamacpp", "litellm"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert "function axisT(pts)" in html, f"{name}: missing span-aware axisT"
        # axis label maps go through axisT(...), not the old per-window fmtT
        assert "axisT(pts)" in html or "axisT(feed.points)" in html, \
            f"{name}: chart labels not built from axisT"
        assert 'WIN==="12mo"' not in html and 'WIN==="30d"' not in html, \
            f"{name}: axis format still keyed off the window name, not the data span"
        # the span thresholds (≈2 days, ≈180 days) drive month/day/time granularity
        assert "180*86400" in html and "2*86400" in html, \
            f"{name}: axisT missing span thresholds"


def test_axisT_granularity_by_span_behavior():
    """Behavioral guard for the reported "days wrong" bug: axisT must pick the
    label granularity from the DATA span — time for ≤2d, calendar day for
    ≤180d, month+'yy beyond — not from the window name. Runs the real JS via
    node (skipped if node is unavailable)."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"function axisT\(pts\)\{[\s\S]*?\n\}", html)
    assert m, "axisT not found in index.html"
    t0 = 1700000000                       # fixed epoch; no Date.now in the logic
    script = m.group(0) + f"""
const t0={t0}, day=86400;
const P = s => [{{t:t0}}, {{t:t0+s}}];
console.log(JSON.stringify([
  axisT(P(3600))(t0),        // 1h span  -> time
  axisT(P(3*day))(t0),       // 3d span  -> "Mon D"
  axisT(P(300*day))(t0),     // 300d span-> "Mon 'YY"
]));
"""
    out = subprocess.run([node, "-e", script], capture_output=True,
                         text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    hour, days, year = json.loads(out.stdout)
    assert re.match(r"^\d{1,2}:\d{2}", hour), f"hour span not a time: {hour!r}"
    assert re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}$", days), \
        f"day span not 'Mon D': {days!r}"
    assert re.match(r"^[A-Z][a-z]{2} '\d{2}$", year), \
        f"year span not \"Mon 'YY\": {year!r}"


def test_all_windowed_pages_have_full_window_set():
    # every dashboard with a time-window selector must offer the SAME set of
    # windows — incl. 30d + 12mo — and carry them in WSECS so pan works. (ollama
    # was missing 12mo; this guards against any page drifting again.)
    for name in ("index", "gpu", "ollama", "llamacpp", "litellm"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        for w in ("15m", "1h", "24h", "30d", "12mo"):
            assert f'data-w="{w}"' in html, f"{name}: missing window button {w}"
        assert '"12mo":31536000' in html, f"{name}: 12mo not in WSECS (pan breaks)"


def test_every_windowed_loader_is_in_the_reload_path():
    # QA guard: any JS loader that fetches a `?window=` endpoint MUST be called in
    # the window-change reload path (rangedReload), else its card silently ignores
    # the time-window selector — exactly how the Per-model table regressed. The
    # export button reads the window too but is a download, not a card → excluded.
    for name in ("index", "gpu", "ollama", "llamacpp", "litellm"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        m = re.search(r"function rangedReload\(\)\{([^}]*)\}", html)
        assert m, f"{name}: no rangedReload()"
        reload_body = m.group(1)
        loaders = set()
        for mm in re.finditer(r'window="\+WIN', html):
            nl = html.rfind("\n", 0, mm.start())
            line = html[nl:html.find("\n", mm.start())]
            if "/api/export" in line:        # download button, not a card loader
                continue
            fns = re.findall(r"function\s+([A-Za-z_]\w*)\s*\(", html[:mm.start()])
            if fns:
                loaders.add(fns[-1])         # nearest enclosing function
        missing = [f for f in loaders
                   if f != "rangedReload" and (f + "(") not in reload_body]
        assert not missing, \
            f"{name}: windowed loaders ignore the selector (not in reload): {missing}"


def test_per_characteristic_charts_defined():
    html = WEB.read_text(encoding="utf-8")
    assert 'id="chart-grid"' in html and 'id="card-gpu"' in html
    # one graph per characteristic, built from the CHARTS config
    # NB: vram_used / vram_pct intentionally NOT charted here — unified-memory
    # GPUs (GB10) report no separate VRAM, so those tiles were always empty.
    for key in ('"cpu"', '"mem"', '"disk"', '"load1"', '"gpu"',
                '"wait"', '"tok"', '"power"', '"gtemp"', '"slots"',
                '"reqrate"', '"tok_in"', '"tok_out"', '"errrate"',
                '"costrate"', '"kvcache"', '"tokwatt"', '"backlog"',
                '"ttft"', '"cachehit"'):
        assert key in html, f"missing chart for {key}"


def test_windowed_pages_have_time_nav_arrows():
    # every dashboard with a time-window selector also has ◀ / ▶ pan arrows
    for name in ("index", "litellm", "gpu", "ollama", "llamacpp"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'id="nav-left"' in html and 'id="nav-right"' in html, name
        assert "TIMEEND" in html and 'end="+TIMEEND' in html, name   # panned query
        assert 'id="range-lbl"' in html, name


def test_litellm_per_model_table_follows_window():
    # the Per-model table must be window-aware (loadModels -> /api/litellm/models,
    # reloaded on window change), not a fixed "rolling window" snapshot
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert "async function loadModels()" in html
    assert "/api/litellm/models?window=" in html
    assert 'id="ll-models-win"' in html                 # window shown in header
    assert "Per-model (rolling window)" not in html     # old fixed label gone
    # reloaded when the window changes (rangedReload) — not just once
    assert html.count("loadModels()") >= 3


def test_litellm_has_window_delta_key_chart():
    # new "requests in window" (delta) bar chart alongside the over-time keys chart
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert 'id="keydelta-chart"' in html
    assert "/api/keydelta" in html and "loadKeyDelta" in html and "keyDeltaChart" in html
    # it is a timeline (line chart plotting per-interval points), not a bar
    assert 'type:"line"' in html and "d.points" in html


def test_litellm_has_per_user_usage_charts():
    """The keys usage charts (bar 'by requests' + delta 'requests in window') each
    have a per-USER sibling that aggregates keys by owner client-side, using the
    alias→owner map built from /api/budgets (keys with no owner fall back to the key)."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    # the two new cards + their canvases
    assert 'id="card-userkeys"' in html and 'id="user-keys-chart"' in html
    assert 'id="card-userdelta"' in html and 'id="userdelta-chart"' in html
    assert "Top 10 API users by requests" in html
    assert "Top 10 API users — requests in window" in html
    # the aggregation wiring: owner map from budgets + the two render/load funcs
    assert "buildKeyUser" in html and "_keyUser" in html and "userOf(" in html
    assert "renderUserKeys" in html and "userKeysChart" in html
    assert "loadUserDelta" in html and "userDeltaChart" in html
    # user-delta reuses the keydelta endpoint and is refreshed on window change/pan
    assert html.count("loadUserDelta(") >= 3   # def + rangedReload + window handler


def test_windowed_pages_have_live_button():
    # a "Live" button jumps the window back to the current time (TIMEEND=null),
    # enabled only when panned into history.
    for name in ("index", "litellm", "gpu", "ollama", "llamacpp"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'id="nav-live"' in html, name
        # click handler snaps to live; disabled state tracks TIMEEND
        assert 'getElementById("nav-live").addEventListener' in html, name
        assert "TIMEEND=null; updateRangeUI()" in html, name
        assert '_liveBtn.disabled=!TIMEEND' in html, name


def test_overview_charts_grouped_collapsible():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert "chart-group" in html and "group-hd" in html
    assert ".chart-group.collapsed" in html          # collapse CSS
    assert 'aimon_g_' in html                         # per-group persistence
    # charts tagged into Host / GPU / LLM groups
    for g in ('g:"Host"', 'g:"GPU"', 'g:"LLM"'):
        assert g in html, f"charts not grouped into {g}"


def test_all_pages_have_alert_dot():
    # live alert dot + unconfigured-backend nav filter on every authenticated page,
    # incl. admin + account (parity with the dashboards)
    for name in ("index", "spend", "litellm", "gpu", "ollama", "llamacpp", "alerts",
                 "admin", "account"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert "has-alert" in html and "_alertDot" in html, name
        assert "/api/alerts" in html, name           # polls active alerts
        assert "/api/nav" in html, name              # hides unconfigured backends
        # the alert-dot interval must be tracked + cleared (no leaked timer)
        assert "_timers" in html and "beforeunload" in html, name


def test_all_pages_have_collapsible_sidebar():
    # lateral collapsible sidebar (AntiBot GW pattern) on EVERY authenticated page —
    # the dashboards AND the admin (/admin/users) + account pages. Only /login is
    # exempt (pre-auth, no menu). The main content sits in #main-area beside it.
    for name in ("index", "spend", "litellm", "gpu", "ollama", "llamacpp", "alerts",
                 "admin", "account"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'id="sidebar-nav"' in html, f"{name}: no sidebar"
        assert 'id="sidebar-toggle"' in html and 'id="sidebar-reopen"' in html, name
        assert 'id="main-area"' in html, f"{name}: content not wrapped in #main-area"
        assert "sb-collapsed" in html and "aimon_sb" in html, name   # collapse + persist
        # all six sections reachable from the sidebar
        for href in ('href="/"', 'href="/spend"', 'href="/litellm"', 'href="/gpu"',
                     'href="/ollama"', 'href="/llamacpp"', 'href="/alerts"'):
            assert href in html, f"{name}: sidebar missing {href}"


def test_login_page_has_no_sidebar():
    # /login is pre-auth: it must NOT show the nav menu (nothing to navigate to yet).
    html = (ROOT / "web" / "login.html").read_text(encoding="utf-8")
    assert 'id="sidebar-nav"' not in html


def test_all_pages_have_theme_toggle():
    # day/night toggle present on every dashboard + shared via localStorage
    for name in ("index", "spend", "litellm", "gpu", "ollama", "llamacpp", "alerts"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'id="theme-btn"' in html, f"{name}: no theme button"
        assert 'data-theme="light"' in html, f"{name}: no light palette"
        assert "aimon-theme" in html, f"{name}: theme not persisted"
        # nav links hidden for unconfigured backends — filter targets all backends
        assert "/api/nav" in html, f"{name}: no nav-link filter"
        for be in ("litellm", "gpu", "ollama", "spend"):
            assert f'"{be}"' in html, f"{name}: nav filter missing {be}"
        # Spend & Quota is LiteLLM-derived — its link is gated by the nav "spend" flag
        assert '["spend",n.spend]' in html, f"{name}: /spend link not gated on nav.spend"


def test_dashboard_uptime_and_export_wired():
    html = WEB.read_text(encoding="utf-8")
    assert 'id="card-uptime"' in html and "loadUptime" in html
    assert 'id="export-btn"' in html and "/api/export" in html
    # with no backend history for the window, hide the whole card rather than
    # leave an empty "no backend history yet" tile
    body = html[html.find("async function loadUptime"):]
    body = body[:body.find("function rangedReload")]
    assert 'getElementById("card-uptime")' in body
    assert 'card.style.display = "none"' in body          # empty window → hide
    assert 'card.style.display = ""' in body              # data present → restore


def test_overview_top_apps_and_evolution():
    html = WEB.read_text(encoding="utf-8")
    # top-5 tables
    assert 'id="card-topcpu"' in html and 'id="card-topram"' in html
    assert "renderProcs" in html
    # per-app evolution line charts + endpoint
    assert 'id="cpuevo-chart"' in html and 'id="ramevo-chart"' in html
    assert "loadProcEvo" in html and "/api/procseries" in html


def test_overview_top_ram_shows_system_total():
    """Top-5 RAM must show a system-wide used/total footer so the per-app rows
    (which never sum to host RAM — huge pages / GPU / shmem live outside RSS) have
    context. renderProcs must receive host mem for this."""
    html = WEB.read_text(encoding="utf-8")
    assert "proc-total" in html and "System RAM" in html
    assert "renderProcs(c.procs, c.host)" in html   # host mem passed in


def test_litellm_load_controls_present_and_documented():
    """The busy-proxy load controls must exist in config + be documented, so a
    slammed proxy can be throttled/disabled without code changes."""
    import config
    knobs = ("LITELLM_HEAVY_INTERVAL", "LITELLM_SPEND_ENABLED",
             "LITELLM_SPEND_MAX_ROWS",
             "LITELLM_SPEND_TIMEOUT", "LITELLM_CB_THRESHOLD",
             "LITELLM_CB_COOLDOWN", "LITELLM_SPEND_MAX_BYTES")
    for knob in knobs:
        assert hasattr(config, knob), f"config missing {knob}"
    env_ex = (ROOT / ".env.example").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for var in knobs:
        assert var in env_ex, f".env.example missing {var}"
        assert var in readme, f"README missing {var}"


def test_litellm_heavy_parse_runs_off_event_loop():
    """The /spend/logs aggregation must be dispatched to a thread (asyncio.to_thread)
    so a big log pull never blocks the event loop (F2)."""
    src = (ROOT / "collectors" / "litellm.py").read_text(encoding="utf-8")
    assert "asyncio.to_thread(" in src and "_parse_spend" in src
    # the sync parser must not do any awaiting (it runs in a worker thread)
    parser = src.split("def _parse_spend(", 1)[1].split("\ndef ", 1)[0]
    assert "await" not in parser, "_parse_spend must be pure/synchronous"


def test_version_is_current():
    assert config.VERSION == "AI-Monitoring_1.6.1"


def test_ux_improvements_present():
    """v1.0.1 UX: status strip, metric tooltips, served-by tags, stale-clock
    colouring, and the 'connecting…' state are all wired."""
    html = WEB.read_text(encoding="utf-8")
    assert 'id="status-strip"' in html and "function renderStrip" in html
    assert "const HELP=" in html and "HELP[label]" in html
    assert "function servedBy(" in html and 'class="srv"' in html
    assert 'age>=60?"var(--bad)"' in html and "age>=15" in html
    assert "function errText(" in html and "connecting…" in html
    assert 'class="info"' in html and "unified memory" in html
    assert "request throughput is on the LiteLLM page" in html
    ll = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert "function servedBy(" in ll and 'class="srv"' in ll


def test_overview_metrics_full_width_layout():
    """Metrics-over-time must be a full-width block row — not a grid item relying on
    the unreliable auto-fit `grid-column:1/-1`. main is a flex column, small cards
    live in a nested .grid, the wide charts stack full-width."""
    html = WEB.read_text(encoding="utf-8")
    assert "display:flex" in html and "flex-direction:column" in html   # main = stack
    assert 'class="grid"' in html and 'class="grid-wide"' in html
    assert "grid-column:1/-1" not in html               # the removed quirk-prone hack
    m = re.search(r'<section class="([^"]*)" id="card-charts"', html)
    assert m and "span-2" not in m.group(1), "card-charts must be a full-width block, not span-2"


def test_gpu_vram_tiles_hide_on_unified_memory():
    """When a GPU has no dedicated VRAM (unified memory → vram_total null), the
    dashboard hides the VRAM KPI tile + the VRAM over-time chart tiles."""
    html = WEB.read_text(encoding="utf-8")
    assert "hasVram" in html                       # the guard
    assert 'card.id = cfg.id + "-card"' in html     # chart tiles are addressable
    assert '"c-vram-card","c-vpct-card"' in html    # VRAM charts toggled off


def test_top_apps_is_top_10():
    """Top-apps tables + over-time charts show 10 (not 5), with enough distinct
    colors for 10 lines."""
    html = WEB.read_text(encoding="utf-8")
    assert "Top 10 apps · CPU" in html and "Top 10 apps · RAM" in html
    assert "Top 5 apps" not in html
    assert "procs.sample, 10" in (ROOT / "app.py").read_text(encoding="utf-8")
    colors = re.search(r"PROC_COLORS=\[([^\]]*)\]", html, re.S)
    assert colors and colors.group(1).count("#") >= 10, "need ≥10 colors for 10 lines"


def test_container_card_shows_down_duration():
    """A stopped/removed container must still render (as down) with how long it's
    been down — the card can't silently drop containers."""
    html = WEB.read_text(encoding="utf-8")
    r = html.split("function renderContainers", 1)[1].split("\nfunction ", 1)[0]
    assert "down_s" in r and "fmtDur(x.down_s" in r
    assert 'dot down' in r                      # red dot for not-running
    assert "uptime / down" in r                 # column header
    # small show/hide-exited toggle, persisted
    assert 'id="cont-toggle"' in r and "aimon_show_exited" in html
    assert "exited (" in r and "_showExited" in html
    # default = exited hidden (only running shown until the user opts in)
    assert '(localStorage.getItem("aimon_show_exited") ?? "0") === "1"' in html


def test_vram_charts_removed_on_unified_memory():
    """VRAM used/% charts are gone — GB10 unified memory reports no separate VRAM,
    so those tiles were permanently empty. (KPIs stay, guarded by vram_total.)"""
    for name in ("index", "gpu"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        charts = html.split("const CHARTS", 1)[1].split("];", 1)[0]
        assert 'key:"vram_used"' not in charts, f"{name}: VRAM used chart still present"
        assert 'key:"vram_pct"' not in charts, f"{name}: VRAM % chart still present"


def test_empty_charts_auto_hidden():
    """Every charted dashboard hides a tile whose metric has no data in the window
    (e.g. LiteLLM latency under spend_mode=lite) — self-healing when data returns."""
    for name in ("index", "gpu", "litellm", "llamacpp"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'cfg.id+"-card"' in html, f"{name}: chart tiles have no -card id"
        assert 'pts.some(p=>p[cfg.key]!=null)' in html, f"{name}: no all-null hide"


def test_health_probe_fully_removed():
    """The deployment-probing /health call must NOT exist anywhere — it can freeze
    a unified-memory box. (Cheap /health/liveliness + /health/backlog stay.)"""
    ll = (ROOT / "collectors" / "litellm.py").read_text(encoding="utf-8")
    assert "_do_health" not in ll
    assert 'f"{base}/health"' not in ll and "/health," not in ll
    assert "LITELLM_HEALTH_ENABLED" not in (ROOT / "config.py").read_text(encoding="utf-8")
    for page in ("index.html", "litellm.html"):
        html = (ROOT / "web" / page).read_text(encoding="utf-8")
        assert 'kpi("Healthy"' not in html and 'kpi("Unhealthy"' not in html
        assert "l.healthy" not in html and "l.unhealthy" not in html
    # the cheap probes remain
    assert "/health/liveliness" in ll and "/health/backlog" in ll


def test_litellm_load_shed_wired():
    """Load-shedding must gate both heavy calls and be fed the host load."""
    import config
    assert hasattr(config, "LITELLM_LOAD_SHED")
    ll = (ROOT / "collectors" / "litellm.py").read_text(encoding="utf-8")
    assert "def _load_shed(" in ll and "def note_load(" in ll
    assert ll.count("_load_shed()") >= 2        # gates /health AND /spend/logs
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "litellm.note_load(_load_per_core(snap))" in app


def test_container_monitoring_wired():
    """Container liveness/alive-time feature is fully wired: config knob, collector,
    decoupled backend loop, snapshot inclusion, and the dashboard card + renderer."""
    import config
    assert hasattr(config, "MONITOR_CONTAINERS") and hasattr(config, "DOCKER_SOCKET")
    assert (ROOT / "collectors" / "containers.py").exists()
    appsrc = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "containers" in appsrc and '_backend_loop(\n            "containers"' in appsrc \
        or '"containers"' in appsrc            # loop + snapshot
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert 'id="card-containers"' in html and "renderContainers(" in html
    assert "fmtDur(" in html                   # alive-time formatting
    env_ex = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "MONITOR_CONTAINERS" in env_ex


def test_app_uses_typed_appkeys():
    """App state uses typed web.AppKey (aiohttp-recommended), not deprecated string
    keys — avoids NotAppKeyWarning + gives type safety."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "web.AppKey(" in src
    for legacy in ('app["session"]', 'app["sampler"]', 'app["backends"]',
                   'request.app["session"]'):
        assert legacy not in src, f"legacy string app key still present: {legacy}"


def test_db_connect_is_closing_context_manager():
    """_connect() must be a commit-and-CLOSE context manager (sqlite's own
    `with conn:` never closes → ResourceWarning leak)."""
    src = (ROOT / "db.py").read_text(encoding="utf-8")
    cm = src.split("def _connect(", 1)[1].split("\ndef ", 1)[0]
    assert "@contextmanager" in src.split("def _connect(", 1)[0][-60:]
    assert "conn.close()" in cm and "conn.commit()" in cm and "conn.rollback()" in cm


def test_backends_decoupled_from_host_sampling():
    """The main sampler must not await ANY blocking collector inline — HTTP
    backends AND gpu (a subprocess that can wedge) run in their own loops, so
    nothing can stall host/procs (the stale-data / wedged-loop bug)."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    body = src.split("async def _sample_once", 1)[1].split("\nasync def ", 1)[0]
    for call in ("litellm.sample(", "ollama.sample(", "llamacpp.sample(",
                 "gpu.sample("):
        assert call not in body, f"_sample_once must not call {call} inline"
    assert "_backend_loop(" in src and '"backends"' in src
    # host/procs (pure /proc, non-blocking) are still sampled fresh every tick
    assert "host.sample" in body and "procs.sample" in body


def test_sampler_loops_are_wedge_proof():
    """Every place a collector is awaited must be time-bounded so a hung call
    (wedged nvidia-smi, slow proxy) can NEVER freeze the loop forever — the bug
    that left host CPU/RAM frozen at the load-spike moment."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    # backend loops bound each sample with wait_for
    bl = src.split("async def _backend_loop", 1)[1].split("\nasync def ", 1)[0]
    assert "asyncio.wait_for(" in bl and "TimeoutError" in bl
    # the main tick is itself watchdogged
    loop = src.split("async def _sampling_loop", 1)[1].split("\nasync def ", 1)[0]
    assert "asyncio.wait_for(_sample_once(" in loop
    # gpu is sampled through the bounded backend machinery, not inline
    assert "_gpu_sample" in src and '_backend_loop("gpu"' in src


def test_litellm_heavy_calls_freeze_safe():
    """Guard the anti-freeze properties so they can't silently regress: the heavy
    /spend/logs call is behind a circuit breaker, with json.loads off the event
    loop and a response size cap."""
    src = (ROOT / "collectors" / "litellm.py").read_text(encoding="utf-8")
    # circuit breaker gates the heavy call
    assert "_cb_open(" in src and "_cb_record(" in src
    # json.loads happens inside the thread-run parser, never on the loop
    assert "def _parse_spend_bytes(" in src
    loop_side = src.split("async def _heavy_sample", 1)[1].split("def _parse_spend_bytes", 1)[0]
    assert "json.loads(" not in loop_side, "json.loads() must run off the event loop"
    # size cap enforced before deserialize
    assert "LITELLM_SPEND_MAX_BYTES" in src and "too_big" in src


def test_alerts_module_webhook_only():
    src = (ROOT / "alerts.py").read_text(encoding="utf-8")
    assert "ALERT_WEBHOOK_URL" in src
    # other channels removed
    for ch in ("TELEGRAM", "DISCORD", "SLACK", "SMTP", "_send_email"):
        assert ch not in src, f"alerts.py still references removed channel {ch}"
    # recovery + debounce behavior intact
    assert "recovered" in src and "_due" in src


def test_litellm_page_exists_and_secure():
    page = ROOT / "web" / "litellm.html"
    assert page.exists(), "second LiteLLM dashboard missing"
    html = page.read_text(encoding="utf-8")
    # dedicated LiteLLM time-series charts (Ollama lives on its own /ollama page)
    for key in ('"wait"', '"reqrate"', '"tok_in"', '"tok_out"', '"errrate"',
                '"costrate"', '"backlog"', '"p50"', '"p95"', '"p99"', '"conc"'):
        assert key in html, f"litellm page missing chart {key}"
    assert "SLO" in html   # SLO tile
    # strict separation: no Ollama panels/charts on the LiteLLM page
    assert "renderOllama" not in html and 'id="card-ollama"' not in html
    assert '"orun"' not in html and '"ovram"' not in html
    # top-10 API keys bar chart
    assert 'id="keys-chart"' in html and "renderKeys" in html
    # load-vs-impact correlation chart (req/s vs GPU/KV/llama-CPU+RAM) + loader
    assert 'id="impact-chart"' in html and "loadImpact" in html
    assert 'id="card-impact"' in html
    assert '"llama.cpp CPU %"' in html and '"llama.cpp RAM %"' in html
    # dedicated over-time charts: one CPU, one RAM (per serving process)
    assert 'id="svc-cpu-chart"' in html and 'id="svc-ram-chart"' in html
    assert "svcCpuChart" in html and "svcRamChart" in html
    # per-model resource cost columns sourced from the procs collector
    assert "svcProc" in html and "svc CPU" in html and "svc RAM" in html
    assert 'type:"bar"' in html
    # top-10 keys OVER TIME — multi-line, one color per key
    assert 'id="keytime-chart"' in html and "loadKeyTime" in html
    assert "/api/keyseries" in html and "KEY_COLORS" in html
    # per-key anomaly panel
    assert 'id="card-anomalies"' in html and "loadAnomalies" in html
    assert "/api/anomalies" in html
    # failed-request viewer (#2) + concurrency-vs-latency (#1) + per-model SLO (#3)
    assert 'id="card-failures"' in html and "renderFailures" in html
    assert 'id="corr-chart"' in html and "loadCorr" in html
    assert "p95" in html and "SLO" in html
    # same §17 invariants as the main dashboard
    assert html.count("function escapeHtml") == 1
    assert len(re.findall(r'innerHTML\s*=', html)) == 1
    assert "DOMPurify.sanitize" in html
    assert "_timers.forEach(clearInterval)" in html
    # cross-links between the two dashboards
    assert '/litellm' in (ROOT / "web" / "index.html").read_text(encoding="utf-8")


def test_alerts_module_covers_anomaly_channel():
    # anomalies flow through the same notifier (extra_breaches path)
    src = (ROOT / "alerts.py").read_text(encoding="utf-8")
    assert "extra_breaches" in src
    anom = (ROOT / "anomaly.py").read_text(encoding="utf-8")
    assert "spike" in anom and "budget" in anom


def test_alerts_page_exists_and_secure():
    page = ROOT / "web" / "alerts.html"
    assert page.exists(), "alerts dashboard missing"
    html = page.read_text(encoding="utf-8")
    assert "Send test alert" in html and "/api/alerts/test" in html
    assert "/api/alerts" in html and "Channels" in html and "Alert history" in html
    # §17 invariants
    assert html.count("function escapeHtml") == 1
    assert len(re.findall(r'innerHTML\s*=', html)) == 1
    assert "DOMPurify.sanitize" in html
    assert "_timers.forEach(clearInterval)" in html
    assert '/alerts' in (ROOT / "web" / "index.html").read_text(encoding="utf-8")


def test_gpu_page_exists_and_secure():
    page = ROOT / "web" / "gpu.html"
    assert page.exists(), "GPU dashboard missing"
    html = page.read_text(encoding="utf-8")
    # vram_pct / vram_used charts removed — unified-memory GPUs report no VRAM
    for key in ('"gpu"', '"power"', '"gtemp"', '"tokwatt"'):
        assert key in html, f"gpu page missing chart {key}"
    assert html.count("function escapeHtml") == 1
    assert len(re.findall(r'innerHTML\s*=', html)) == 1
    assert "DOMPurify.sanitize" in html
    assert "_timers.forEach(clearInterval)" in html
    assert '/gpu' in (ROOT / "web" / "index.html").read_text(encoding="utf-8")


def test_ollama_page_exists_and_secure():
    page = ROOT / "web" / "ollama.html"
    assert page.exists(), "Ollama dashboard missing"
    html = page.read_text(encoding="utf-8")
    for key in ('"orun"', '"oram"', '"ovram"'):
        assert key in html, f"ollama page missing chart {key}"
    assert "Active running models" in html   # the requested view
    assert html.count("function escapeHtml") == 1
    assert len(re.findall(r'innerHTML\s*=', html)) == 1
    assert "DOMPurify.sanitize" in html
    assert "_timers.forEach(clearInterval)" in html
    assert '/ollama' in (ROOT / "web" / "index.html").read_text(encoding="utf-8")


def test_deploy_helpers_present():
    assert (ROOT / "deploy" / "tunnel.sh").exists()
    assert (ROOT / "deploy" / "ai-monitoring.container.service").exists()
    assert (ROOT / "deploy" / "build-multiarch.sh").exists()
    assert (ROOT / "deploy" / "docker-compose.server.yml").exists()


def test_docs_present_and_current():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    arch = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert len(readme) > 2000 and len(arch) > 1500, "docs too thin"
    # README documents every dashboard route + the config sections
    for k in ("/litellm", "/gpu", "/ollama", "/alerts", "Configuration",
              "Retention", "Deployment", "Security"):
        assert k in readme, f"README missing '{k}'"
    # every .env-facing config var (from .env.example) is documented in README
    env_vars = [ln.split("=", 1)[0] for ln in
                (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
                if ln and not ln.startswith("#") and "=" in ln]
    for var in ("MONITOR_DASHBOARD_TOKEN", "ROLLUP_HOUR_DAYS", "ANOMALY_FACTOR",
                "ALERT_WEBHOOK_URL", "GPU_SSH", "SLO_LATENCY_MS"):
        assert var in env_vars, f".env.example lost {var}"
        assert var in readme, f"README missing config var {var}"


def test_startup_selfcheck_clean():
    # the per-run boot smoke check must pass in a healthy checkout
    import app
    assert app.startup_selfcheck() == []


def test_dockerfile_gates_build_on_tests():
    # QA must run on every build: a `test` stage runs pytest and the runtime
    # stage depends on its marker, so a regression fails `docker build`.
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "AS test" in df and "pytest" in df
    assert "COPY --from=test /qa-passed" in df


def test_every_metric_column_charted_somewhere():
    # regression guard: any new db metric column must appear as a chart key in
    # at least one dashboard, else it silently never gets graphed.
    import db
    pages = "".join(p.read_text(encoding="utf-8")
                    for p in (ROOT / "web").glob("*.html"))
    # unified-memory GPUs (GB10) report no separate VRAM → these columns are
    # still collected (ollama fallback / alerts) but intentionally uncharted.
    for col in db._METRIC_COLS:
        if col in ("vram_total", "vram_used", "vram_pct"):
            continue
        assert f'"{col}"' in pages, f"metric {col} has no chart on any dashboard"


def test_llm_cards_hidden_by_default():
    # rules: with no backend the LLM panels must not show — hidden until configured
    html = WEB.read_text(encoding="utf-8")
    for cid in ("card-litellm", "card-ollama", "card-llamacpp"):
        m = re.search(rf'id="{cid}"[^>]*style="display:none"', html)
        assert m, f"{cid} must default to display:none"
    # and rendering is gated on isConfigured
    assert html.count("isConfigured(") >= 3


# ------------------------------------------------------ container hardening ---
def test_dockerfile_nonroot_and_healthcheck():
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r'^USER\s+monitor', df, re.M), "container must run non-root"
    assert "HEALTHCHECK" in df
    assert "/healthz" in df


def test_dockerfile_alpine_multiarch_hardened():
    # Alpine base (0 HIGH/CRITICAL vs 11 on Debian slim) + multi-arch build knobs
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "python:3.14-alpine" in df, "base must be Alpine (vuln-minimal)"
    assert "ARG RUN_TESTS" in df, "cross-arch builds need a test-skip toggle"
    assert "--upgrade pip" in df, "pip must be upgraded (clears pip CVEs)"
    assert "adduser" in df and "USER monitor" in df   # non-root on BusyBox
    assert (ROOT / "deploy" / "build-multiarch.sh").exists()


def test_dockerfile_copies_every_top_level_module():
    # guard: every top-level .py the app imports must be COPYed into the image
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for mod in ("config.py", "db.py", "app.py", "alerts.py", "anomaly.py"):
        assert mod in df, f"Dockerfile does not COPY {mod} — container will crash"


# ══════════════════════════════════════════════════════════════════════════════
# Extra QA — 1.4.0 dependency / CI toolchain bumps (Dependabot #1/#2/#4)
# ══════════════════════════════════════════════════════════════════════════════
def test_trivyignore_accepts_hostpid_with_reason():
    # The CI Trivy filesystem scan flags AVD-KSV-0010 (DaemonSet hostPID:true).
    # That is required by design for the host-process (top-N CPU/RAM) collector,
    # so it is an ACCEPTED risk documented in .trivyignore — not a silent mute.
    ti = ROOT / ".trivyignore"
    assert ti.exists(), ".trivyignore missing — CI fs scan will stay red on hostPID"
    body = ti.read_text(encoding="utf-8")
    # the id must be present as its own (non-comment) line
    ids = [ln.strip() for ln in body.splitlines()
           if ln.strip() and not ln.lstrip().startswith("#")]
    assert "AVD-KSV-0010" in ids, "AVD-KSV-0010 must be an active ignore entry"
    low = body.lower()
    assert "hostpid" in low and ("by design" in low or "accepted" in low), \
        "every .trivyignore entry must document why it is accepted"


def test_trivyignore_is_published():
    # the ignore file only helps CI if the publish ALLOW-list actually ships it
    pub = ROOT / "deploy" / "publish-github.sh"
    if not pub.exists():           # publish script is not always vendored
        return
    assert ".trivyignore" in pub.read_text(encoding="utf-8"), \
        ".trivyignore must be in the publish ALLOW-list or CI never sees it"


def test_requirements_dev_pins_pytest9_toolchain():
    req = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "pytest>=9.1.1,<10" in req, "pytest must be pinned to the 9.x line"
    assert "pytest-asyncio>=1.4.0" in req, "pytest-asyncio must be the 1.x line"


def test_ci_actions_pinned_to_current_majors():
    # Dependabot #4 — the pinned action versions CI runs on. Stale pins reopen
    # the same PR every week and (for checkout<v7) carry the node20 deprecation.
    want = {
        ".github/workflows/ci.yml": [
            "actions/checkout@v7", "aquasecurity/trivy-action@v0.36.0",
        ],
        ".github/workflows/release.yml": [
            "actions/checkout@v7", "docker/setup-qemu-action@v4",
            "docker/setup-buildx-action@v4", "docker/login-action@v4",
            "docker/build-push-action@v7",
        ],
    }
    for rel, pins in want.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        lines = text.splitlines()
        for pin in pins:
            action, _, ver = pin.rpartition("@")     # "actions/checkout", "v7"
            # Accept the bare tag (action@v7) OR the hardened SHA-pin form with the
            # version in a comment (action@<sha> # v7.0.0) — SHA pinning is the
            # supply-chain best practice and must not trip this test.
            tag_form = pin in text
            sha_form = any(action in ln and f"# {ver}" in ln for ln in lines)
            assert tag_form or sha_form, f"{rel} must pin {action} to {ver}"
        # no stale predecessor left behind (neither a v5 tag nor a '# v5' SHA comment)
        assert "actions/checkout@v5" not in text and "checkout@" in text \
            and not any("actions/checkout" in ln and "# v5" in ln for ln in lines), \
            f"{rel} has a stale checkout pin"


def test_chart_text_colors_are_theme_resolved_not_hardcoded():
    """Chart.js axis/legend TEXT must resolve from the theme var (cssv('--muted') /
    cssv('--fg')) — never a hardcoded dark-theme hex. `#8b949e` on the light theme's
    white is only ~2.8:1 (fails WCAG AA) and `#e6edf3` is invisible on white; both
    were literal Chart tick colors. Guards light-theme legibility."""
    for name in ("index", "litellm", "gpu", "ollama", "llamacpp", "spend"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        # the readable-in-both-themes muted var is used for chart text
        assert 'cssv("--muted")' in html, f"{name}: chart text not theme-resolved"
        # no hardcoded dark-theme greys/whites as a quoted Chart color literal
        assert '"#8b949e"' not in html, f"{name}: hardcoded #8b949e chart color"
        assert '"#e6edf3"' not in html, f"{name}: hardcoded #e6edf3 chart color"
        # the var-definition of --muted stays (it's the dark-theme default, themed over)
        assert "--muted:#8b949e" in html


def test_spend_has_cost_per_model_over_time_card():
    """A 'Cost per model over time' chart card sits above Per-key budgets, driven by
    /api/spend/model-series, real=solid vs estimated=dashed lines."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    assert 'id="card-model-cost-time"' in html and 'id="model-cost-chart"' in html
    assert "loadModelCostSeries" in html and "/api/spend/model-series" in html
    assert "renderModelCostTime" in html
    # placed ABOVE the per-key budgets card
    assert html.index('id="card-model-cost-time"') < html.index('id="card-keys"')
    # estimated series drawn dashed (kind !== real)
    assert 'borderDash:est?[5,3]:[]' in html


def test_all_dashboard_charts_update_in_place_not_rebuilt():
    """Every dashboard polls on an interval; multi-series charts must refresh via
    updateSeries() — updating dataset VALUES in place (and preserving the user's legend
    toggles by key when the series set changes) — never by replacing the whole
    chart.data.datasets array, which reset selections and re-animated. Guards all charts."""
    # pages with dynamic multi-series charts: the helper + no caller-side full rebuild
    for name in ("index", "litellm", "gpu", "spend"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert "function updateSeries" in html, f"{name}: missing updateSeries helper"
        # helper: in-place value update + toggle-preserving rebuild
        assert "cur[i].data=d.data" in html, f"{name}: helper doesn't update in place"
        assert "isDatasetVisible(i)" in html and "hidden=true" in html, \
            f"{name}: helper doesn't preserve legend toggles"
        # BAN a caller rebuilding a chart's whole datasets array (only the helper may,
        # as `chart.data.datasets=next`).
        offenders = [ln.strip() for ln in html.splitlines()
                     if ".data.datasets=" in ln and "datasets=next" not in ln]
        assert not offenders, f"{name}: caller rebuilds datasets (use updateSeries): {offenders}"
    # single fixed-dataset chart pages update .data in place already (no full rebuild)
    for name in ("ollama", "llamacpp"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        offenders = [ln.strip() for ln in html.splitlines()
                     if ".data.datasets=" in ln and "datasets=next" not in ln]
        assert not offenders, f"{name}: rebuilds datasets: {offenders}"


def test_spend_charts_keep_selection_across_poll():
    """The Spend page polls every 5s; chart interactions must survive it. The
    cost-per-model chart preserves hidden model lines (by name) across the datasets
    rebuild, and the cost-by-user chart re-opens the expanded selection."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    # model-cost lines refresh via the shared updateSeries helper, keyed by model name
    # (it preserves legend toggles + updates values in place)
    assert "updateSeries(modelCostChart" in html and "_k:m.model" in html
    # cost-by-user expanded selection remembered + restored on re-render
    assert "_costOpen" in html and "rows.find(r=>r.name===_costOpen)" in html


def test_spend_budget_table_is_paginated():
    """Per-key budgets table shows 20 per page (ranked by risk) with Prev/Next paging;
    the backend still returns every key (pagination is display-only)."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    assert "KEYS_PER_PAGE=20" in html
    assert "_keysPage" in html                         # current-page state
    assert 'data-pg="prev"' in html and 'data-pg="next"' in html
    assert "keys.slice(pStart,pEnd)" in html           # only the page is rendered
    assert "of ${total} · ranked by risk" in html      # "X–Y of N" range label
    assert 'class="kpager"' in html


def test_spend_cost_chart_groups_by_user_and_expands_keys():
    """Spend "Cost by user": the cumulative-cost bar chart defaults to grouping spend
    by USER (email), with a user/key/team toggle, and clicking a user/team bar expands
    a panel listing the keys behind it. Guards the grouping + click wiring + safety."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    # card renamed + user is the DEFAULT grouping
    assert "Cost by user" in html
    assert 'let COSTBY="user"' in html
    # three toggles, "by user" active by default
    for by in ("user", "key", "team"):
        assert f'data-by="{by}"' in html, f"cost toggle missing by-{by}"
    assert 'data-by="user" class="active"' in html
    # grouping logic: user → email (fallback "Unassigned"), team → team, key → key;
    # every group carries its underlying keys for the click-to-expand
    assert 'k.email||"Unassigned"' in html
    assert "COSTBY===\"user\"" in html and "COSTBY===\"team\"" in html
    assert "keys:v.keys" in html            # grouped rows keep their keys
    # click a bar → showCostKeys lists that group's keys (wired via chart onClick)
    assert "onClick:(e,els)" in html and "showCostKeys" in html and "_costRows" in html
    assert "click a user to see the keys they used" in html
    # the detail panel is DOM-safe (escaped) and never innerHTML-raw
    assert "function showCostKeys" in html
    assert "escapeHtml(k.key)" in html and "escapeHtml(row.name)" in html
    # regression: no fixed top-N cap — every row shown (bars sized by count)
    assert ".slice(0,12)" not in html and "rows.length*24" in html


def test_spend_budget_card_shows_owner_details():
    """Per-key budgets card enriches each row with the owner email and a click-to-
    expand details panel (ID · username · email · team · key), mirroring the Settings
    Teams board. Guards the renderKeys wiring + the fields it reads."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    assert "renderKeys" in html
    # owner email subline + the clickable key that toggles the detail row
    assert 'class="kemail"' in html and 'class="kx"' in html
    assert "Click for details" in html
    # the structured detail rows read email + user off the budget row
    assert "r.email" in html and "r.user" in html
    for label in ("User ID", "Username", "Email", "Team", "Key"):
        assert label in html, f"budget owner-detail missing '{label}' row"
    # header leads with the owner username → "User / key"
    assert "User / key" in html
    # the row's main label is the owner username (email local part), key as fallback
    assert 'email.split("@")[0]:r.key' in html


def test_supply_chain_scorecard_invariants():
    """Lock in the OpenSSF Scorecard checks that reached 10/10 so a later edit can't
    silently regress them: SHA-pinned actions, minimal top-level workflow permissions,
    a digest-pinned base image, and the SAST/Fuzzing/Scorecard workflows + fuzz
    harness present (and in the publish ALLOW-list). See rules.md §9a."""
    wf_dir = ROOT / ".github" / "workflows"
    workflows = sorted(wf_dir.glob("*.yml"))
    assert workflows, "no CI workflows found"

    for w in workflows:
        text = w.read_text(encoding="utf-8")
        # (a) every `uses:` is SHA-pinned (40 hex), never a mutable @vN / @main / branch
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.search(r"uses:\s*([^\s@]+)@(\S+)", ln)
            if m:
                assert re.fullmatch(r"[0-9a-f]{40}", m.group(2)), \
                    f"{w.name}:{i} action {m.group(1)} not SHA-pinned (@{m.group(2)})"
        # (b) no WRITE at the workflow (top) level — writes escalate per-job only
        top = text.split("\njobs:", 1)[0]
        inline = re.search(r"(?m)^permissions:[ \t]+(\S.*)$", top)
        block = re.search(r"(?m)^permissions:[ \t]*\n((?:[ \t]+\S.*\n)+)", top)
        perm = (inline.group(1) if inline else "") + (block.group(1) if block else "")
        assert "write" not in perm, f"{w.name} grants write at the top (workflow) level"

    # (c) Dockerfile base image pinned by digest (Pinned-Dependencies)
    base = [ln for ln in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
            if ln.startswith("FROM ") and " AS base" in ln]
    assert base and all("@sha256:" in ln for ln in base), \
        "Dockerfile base image must be pinned by @sha256 digest"

    # (d) SAST / Scorecard / Fuzzing workflows + the fuzz harness exist
    for f in ("codeql.yml", "scorecard.yml", "cflite-pr.yml"):
        assert (wf_dir / f).exists(), f"missing security workflow {f}"
    assert (ROOT / "fuzz" / "fuzz_parsers.py").exists(), "missing fuzz harness"
    assert (ROOT / ".clusterfuzzlite" / "Dockerfile").exists(), "missing ClusterFuzzLite config"

    # (e) those files stay in the publish ALLOW-list (the private publisher is
    #     intentionally not published, so skip when it isn't in this checkout)
    pub = ROOT / "deploy" / "publish-github.sh"
    if pub.exists():
        allow = pub.read_text(encoding="utf-8")
        for f in (".github/workflows/codeql.yml", ".github/workflows/cflite-pr.yml",
                  "fuzz/fuzz_parsers.py", ".clusterfuzzlite/Dockerfile",
                  ".clusterfuzzlite/build.sh"):
            assert f in allow, f"publish ALLOW-list missing {f}"


# ══════════════════════════════════════════════════════════════════════════════
# Extra QA — Overview layout regressions (1.0.4)
# ══════════════════════════════════════════════════════════════════════════════
def test_overview_gpu_badge_is_live_not_mode():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert 'gpu-badge"),true,"live"' in html
    # the old "file nvidia" (mode + vendor) badge text must be gone
    assert 'g.mode||"")+" "+(g.vendor' not in html


def test_overview_uptime_stacked_under_gpu():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    i = html.find("flex-direction:column")
    g = html.find('id="card-gpu"', i)
    u = html.find('id="card-uptime"', i)
    assert i >= 0 and 0 < g < u          # gpu card sits above uptime in the column


def test_overview_ram_pressure_banner_wired():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert 'id="ram-banner"' in html
    assert "h.mem_pct>=90" in html       # banner shows only under memory pressure


def test_overview_leads_with_llm_cost_usage_summary():
    # Repositioning (1.4.0): a "LLM usage & cost" hero strip is the FIRST card in
    # <main>, above the infra grid, so spend/tokens/keys are seen first. It binds
    # to the LiteLLM snapshot and hides when no LiteLLM backend is configured.
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert 'id="card-llm-summary"' in html and 'id="llm-summary-kpis"' in html
    assert "function renderLlmSummary(" in html
    assert "renderLlmSummary(c.litellm)" in html          # wired into the render loop
    # it must sit ABOVE the host/infra grid (leads the page)
    assert html.index('id="card-llm-summary"') < html.index('id="card-host"')
    # surfaces the cost/usage numbers, gated on backend being configured
    for tile in ("Spend (window)", "Cost rate", "Tokens", "Requests", "Active keys"):
        assert tile in html, f"summary missing {tile} tile"
    assert 'showCard("card-llm-summary", isConfigured(l))' in html
    # no raw innerHTML sink introduced — uses the sanitized setHtml helper
    assert "renderLlmSummary" in html and "setHtml(box," in html


def test_readme_leads_with_llm_usage_and_states_scope():
    # Repositioning (1.4.0): the README must lead with the LLM usage/cost value
    # prop (not read as "just system monitoring") and set scope so nobody expects
    # SaaS subscription-quota tracking.
    head = "".join((ROOT / "README.md").read_text(encoding="utf-8").splitlines(keepends=True)[:45]).lower()
    assert "usage" in head and "cost" in head and "spend" in head, \
        "README intro must lead with LLM usage/cost/spend"
    assert "what it is" in head and "isn't" in head, \
        "README must carry a 'What it is / isn't' scope note"
    assert "subscription" in head, "scope note must address the subscription-billing expectation"


def test_demo_seed_theme_shim_forwards_kwargs():
    # Regression: the demo server's _serve_page wrapper dropped the user/role
    # kwargs the app now passes, 500-ing every seeded page. It must accept and
    # forward **kw to the original _serve_page.
    src = (ROOT / "scripts" / "demo_seed.py").read_text(encoding="utf-8")
    assert "def _serve_with_theme(path, prefix=\"\", **kw):" in src, \
        "theme shim must accept **kw (else user/role kwargs 500 the page)"
    assert "_orig_serve(path, prefix, **kw)" in src, \
        "theme shim must forward **kw to the real _serve_page"


def test_settings_page_exists_with_tunables_and_teams():
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    assert 'id="board"' in html and 'id="teams"' in html, "settings page missing sections"
    assert "/api/admin/settings" in html and "/api/admin/teams" in html
    # admin-only note + LiteLLM-enterprise team-budgets documentation on the page
    assert "Enterprise" in html and "team budgets" in html.lower()
    # manual team refresh: detected teams are cached (LiteLLM lookup is flaky) and only
    # re-fetched on the Refresh button, which calls the endpoint with ?refresh=1.
    assert 'id="teams-refresh"' in html and "refresh=1" in html
    # the per-row ⟳ re-detects from LiteLLM and lets it WIN — drops the override and
    # reloads the board, overwriting the previously-defined team.
    assert "/api/admin/teams/sync" in html and "LiteLLM wins" in html
    # Teams board is grouped by USER → team → keys (user-centric view), with a per-key
    # sync endpoint and an "Unassigned" bucket for keys LiteLLM reports no owner for.
    # (DOM is built in JS, so match the className strings, not rendered HTML attributes.)
    assert '"urow"' in html and "By user" in html and '"teamcell"' in html
    assert "/api/admin/teams/sync" in html and "__unassigned__" in html
    # grouped list is tall enough for the top users and scrolls; clicking a user name opens
    # a STRUCTURED details panel (User ID · Username · Email · Team · Keys) — the raw UUID
    # lives there, never rendered inline as a truncated slice.
    assert '"uscroll"' in html and "max-height" in html
    assert '"udetails"' in html and "User ID" in html and 'g.uid.slice' not in html
    assert "ranked by usage" in html    # users sorted by spend, top first
    # one block per user in order email → team → keys: email primary, team is a SELECT of
    # the identified teams plus an "add new" option, a per-user budget input, and ALL keys
    # on a single horizontally-scrolling line of chips (not a stacked row per key).
    assert '"kstrip"' in html and '"kchip"' in html and '"urow"' in html
    assert '"tsel"' in html and "__new__" in html and "new team" in html
    assert 'chosenTeam' in html and '"bin"' in html    # team picker + per-user budget
    # reassigning a key's user is restricted to EXISTING users — a dropdown, not free text
    assert "_knownEmails" in html and "existing users only" in html
    assert "/api/admin/key-user" in html
    # config groups + Model-cost rows still use the compact one-line .srow style
    assert '"grid2"' in html and "srow tmodel" in html
    # unified free-form board: any card moves ANYWHERE + resizes (column span), order +
    # sizes persisted SERVER-SIDE in the DB, with grip + resize handles + Reset-layout.
    assert "/api/admin/ui-layout" in html and "loadLayout" in html and "saveLayout" in html
    assert 'id="board"' in html and '"draghandle"' in html and 'id="reset-layout"' in html
    assert "makeResizable" in html and "freeAt" in html and "gridColumn" in html  # 2-D + collision
    assert '"rsz rsz-"+dir' in html and "gridRow" in html                         # w/h/corner handles
    assert 'data-card="l:teams"' in html and 'data-card="l:models"' in html       # Teams/Models on board
    # click a key chip → popup to reassign its user/email (per-key user override)
    assert "openKeyUserPopup" in html and "/api/admin/key-user" in html
    # Teams card: description text moved into a click-the-title info popup (organized)
    assert "openTeamsInfo" in html and '"cardinfo"' in html
    assert "Type a team and click" not in html   # old inline description removed
    # Model costs card: same treatment — description moved into a click-the-title info popup
    assert "openModelsInfo" in html and 'id="models-info"' in html
    assert "drives the split on Spend" not in html   # old inline description removed
    # Page header: the intro paragraph + its ⓘ tooltip moved into a click-the-title popup
    assert "openSettingsInfo" in html and 'id="settings-info"' in html
    assert 'class="intro">Operator tuning' not in html   # old inline intro removed
    # no raw innerHTML sink — the page is built with DOM APIs
    assert not re.search(r"innerHTML\s*=", html), "settings page must not use innerHTML"


def test_dashboards_use_currency_global_not_hardcoded_dollar():
    """Money is rendered via the injected `window.CUR` currency global (default $), not a
    hardcoded `"$"` — so MONITOR_CURRENCY can switch it (e.g. to €) with no code change."""
    # money-rendering pages must use CUR
    for f in ("spend.html", "litellm.html", "settings.html", "index.html"):
        html = (ROOT / "web" / f).read_text(encoding="utf-8")
        assert "CUR" in html, f"{f} should render money via the CUR currency global"
    # NO page may hardcode a "$" money prefix
    for f in ("spend.html", "litellm.html", "settings.html", "index.html", "alerts.html"):
        html = (ROOT / "web" / f).read_text(encoding="utf-8")
        assert '"$"' not in html, f'{f} still hardcodes "$" as a money prefix'


def test_dashboard_inline_scripts_parse():
    """Every inline <script> in the dashboards must be valid JS. Guards against
    edits (e.g. the CUR currency swap) that mangle a string across a newline and
    ship an `Uncaught SyntaxError` to the browser. Skipped if node is absent."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available to syntax-check inline scripts")
    import os
    import tempfile

    _INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)
    for f in ("spend.html", "litellm.html", "settings.html", "index.html", "alerts.html"):
        txt = (ROOT / "web" / f).read_text(encoding="utf-8")
        for i, m in enumerate(_INLINE.finditer(txt)):
            code = m.group(1)
            if not code.strip():
                continue
            tf = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
            tf.write(code)
            tf.close()
            try:
                r = subprocess.run([node, "--check", tf.name], capture_output=True, text=True)
            finally:
                os.unlink(tf.name)
            assert r.returncode == 0, f"{f} inline script #{i} has a JS syntax error:\n{r.stderr}"


def test_settings_model_cost_override_ui():
    """Model-costs card exposes each model's $/1M cost and lets an admin PIN it (per-model
    cost input + action=cost / cost_reset), so an unreliable LiteLLM price can be corrected
    from the UI. Guards the wiring + the fields it reads."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    assert '"min mcost"' in html                             # the per-model cost input (JS-built)
    assert 'action:"cost"' in html and "usd_1m" in html      # Save posts a cost override
    assert 'action:"cost_reset"' in html                     # Reset clears it
    assert "eff_cost_1m" in html and "cost_1m" in html        # shows effective + set $/1M


def test_config_tunables_exclude_secrets_and_switches():
    import config
    # Only non-secret operational tuning is runtime-changeable. Secrets, infra and
    # security switches must NEVER be tunable from the UI.
    forbidden = {
        "MONITOR_DASHBOARD_TOKEN", "MONITOR_METRICS_TOKEN", "LITELLM_MASTER_KEY",
        "LLAMACPP_API_KEY", "GPU_SSH_KEY", "MONITOR_ADMIN_PASSWORD",
        "MONITOR_ALLOW_OPEN", "MONITOR_COOKIE_ALLOW_INSECURE",
        "MONITOR_AUTH_TRUSTED_PROXY", "ALLOW_OPEN", "COOKIE_ALLOW_INSECURE",
        "AUTH_TRUSTED_PROXY", "DASHBOARD_TOKEN", "METRICS_TOKEN",
        "LITELLM_BASE_URL", "OLLAMA_BASE_URL", "LLAMACPP_BASE_URL",
        "MONITOR_HOST", "MONITOR_PORT", "DB_PATH",
    }
    assert not (forbidden & set(config.TUNABLES)), \
        "a secret / infra / security switch leaked into config.TUNABLES"
    assert "ALERT_CPU_PCT" in config.TUNABLES and "SAMPLE_INTERVAL" in config.TUNABLES
    # every tunable spec is well-formed
    for spec in config.TUNABLES.values():
        assert spec["t"] in ("float", "int", "bool", "choice")
        assert "def" in spec and "group" in spec and "label" in spec


# ══════════════════════════════════════════════════════════════════════════════
# Extra QA — 1.0.5 UI + packaging regressions
# ══════════════════════════════════════════════════════════════════════════════
_PAGES = ["index", "gpu", "litellm", "ollama", "llamacpp", "alerts"]
_WINDOWED = ["index", "gpu", "litellm", "llamacpp", "ollama"]   # have the window nav
_LLM_PAGES = ["litellm", "ollama", "llamacpp"]                  # default window = 24h


def _page(name):
    return (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")


def test_sidebar_gpu_between_overview_and_litellm():
    """regression: sidebar order is Overview → GPU → LiteLLM on every page."""
    for name in _PAGES:
        html = _page(name)
        # nav labels carry an icon prefix (e.g. "🏠 Overview"), so anchor on the
        # closing text, not "href=…>Label", which the icon now sits between.
        o = html.find('Overview</a>')
        g = html.find('GPU</a>')
        ll = html.find('LiteLLM</a>')
        assert o >= 0 and g >= 0 and ll >= 0, f"{name}: nav links missing"
        assert o < g < ll, f"{name}: sidebar order must be Overview < GPU < LiteLLM"


def test_metrics_over_time_is_full_width():
    """regression: the charts card spans every grid column (was ~50% at span-2)."""
    for name in ("gpu", "litellm"):
        html = _page(name)
        assert ".span-full{grid-column:1/-1}" in html, f"{name}: .span-full CSS missing"
        assert 'class="card span-full" id="card-charts"' in html, \
            f"{name}: charts card must use span-full, not span-2"


def test_llm_pages_default_to_24h_window():
    """regression: LiteLLM/Ollama/llama.cpp open on a 24h window by default."""
    for name in _LLM_PAGES:
        html = _page(name)
        assert 'let WIN = "24h";' in html, f"{name}: default WIN must be 24h"
        assert '<button data-w="24h" class="active">24h</button>' in html, \
            f"{name}: the 24h button must be the active one"
        assert '<button data-w="1h" class="active">' not in html, \
            f"{name}: the 1h button must no longer be active"


def test_gpu_name_in_header_via_textcontent():
    """regression+security: the single-GPU name sits in the card header and is set
    via textContent (never an innerHTML sink), and the old bottom caption is gone."""
    html = _page("index")
    assert 'id="gpu-name"' in html
    assert "nameEl.textContent" in html            # written safely, no HTML sink
    # the removed bottom caption must not come back
    assert 'proc-total mut">${escapeHtml(g.gpus[0].name' not in html


def test_window_date_range_wired_on_windowed_pages():
    """regression+security: every windowed page shows an absolute start→end range,
    updated via updateRangeUI, and rendered with textContent (not innerHTML)."""
    for name in _WINDOWED:
        html = _page(name)
        assert 'id="range-dates"' in html, f"{name}: range-dates span missing"
        assert "function fmtRange(" in html, f"{name}: fmtRange helper missing"
        assert "_dt.textContent" in html, f"{name}: range dates must use textContent"


def test_license_apache2_present_and_wired():
    """packaging: Apache-2.0 LICENSE exists and is referenced in the README. The
    publish allow-list check runs only where the publisher is checked out (dev tree
    on the Mac); the public repo intentionally excludes deploy/publish-github.sh —
    it embeds a private SSH remote alias and lives in a separate private scripts
    repo — so CI skips that assertion cleanly."""
    lic = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in lic and "Version 2.0" in lic
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Apache License 2.0" in readme
    pub_path = ROOT / "deploy" / "publish-github.sh"
    if not pub_path.exists():
        return   # public checkout: publisher lives in ai_monitoring_scripts, not here
    assert "LICENSE" in pub_path.read_text(encoding="utf-8"), \
        "LICENSE not in publish allow-list"


def test_ci_consolidated_with_per_control_badges():
    """functional: one ci.yml runs every control as a job (+ a badges job), the five
    old split workflows are gone, and the README carries per-control endpoint badges."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for job in ("secret-scan:", "lint:", "tests:", "trivy-fs:", "build-scan:", "badges:"):
        assert job in ci, f"ci.yml missing job {job}"
    assert "schemaVersion" in ci, "badges job must write shields endpoint JSON"
    wf = ROOT / ".github" / "workflows"
    for gone in ("lint.yml", "tests.yml", "trivy-fs.yml", "secret-scan.yml", "build-scan.yml"):
        assert not (wf / gone).exists(), f"stale split workflow {gone} still present"
    assert (wf / "release.yml").exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for ctl in ("secret-scan", "lint", "tests", "trivy-fs", "build-scan"):
        assert f"badges/{ctl}.json" in readme, f"README missing endpoint badge for {ctl}"


def test_gpu_stacked_per_app_cpu_chart():
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    assert 'id="appcpu-chart"' in html and "loadAppCpu" in html
    assert "stacked:true" in html                       # stacked area, not lines
    assert "PROC_COLORS" in html                          # per-app colour palette
    # Stacked-area fill MUST go to the previous dataset, not to zero. fill:true fills
    # to origin, stacking translucent layers so each band blends with the ones below
    # (green→olive, pink→mauve) and no longer matches its legend swatch. The appcpu
    # datasets must fill to the previous line (i?"-1":"origin").
    assert re.search(r'fill:\s*i\s*\?\s*["\']-1["\']\s*:\s*["\']origin["\']', html), \
        "appcpu stacked chart must fill to previous dataset, not to zero"
    assert "/api/procseries?kind=cpu" in html
    # a missing app-in-a-bucket must be 0, NOT null, and spanGaps must be off — else
    # a null gets span-gapped into a phantom diagonal band across the gap.
    assert re.search(r'p\[a\]==null\?0:p\[a\]', html), \
        "absent app must map to 0 (not null) on the stacked chart"
    assert re.search(r'spanGaps:\s*false', html), \
        "stacked appcpu chart must not spanGaps (0-fill instead)"


def test_procs_reader_exposes_top10():
    import db as _db
    import inspect
    assert "top_n: int = 10" in inspect.getsource(_db.proc_series)


def test_overview_host_hardware_popover():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert 'id="host-detail"' in html and "renderHostDetail" in html
    assert ".hw-pop" in html                      # styled popover, not a bare title
    assert "GPU_SPECS" in html and '"GB10"' in html   # curated reference specs


def test_host_collector_emits_static_info():
    import inspect
    from collectors import host
    src = inspect.getsource(host)
    assert "_hw_info" in src and '"info"' in src   # static HW facts in the snapshot
    info = host.sample().get("info", {})
    assert "arch" in info and "cpu_threads" in info


def test_gitleaks_wired_in_secret_scan():
    """security: gitleaks runs alongside TruffleHog in the secret-scan job, with a
    .gitleaks.toml that allowlists the synthetic values in tests/ + .env.example."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    # gitleaks runs as the binary (no deprecated Node 20 action); it scans git
    # history with the repo config.
    assert "gitleaks git . --config .gitleaks.toml" in ci, "gitleaks step missing from CI"
    assert "gitleaks/gitleaks-action" not in ci, "drop the Node 20 marketplace action"
    assert "trufflesecurity/trufflehog" in ci, "TruffleHog must still run too"
    cfg = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    assert "useDefault = true" in cfg          # built-in rule set
    assert "tests/" in cfg and ".env.example" in cfg   # synthetic-secret allowlist
    # publisher lives in a private scripts repo, not published here (see
    # test_license_apache2_present_and_wired for rationale). Skip cleanly in CI.
    pub_path = ROOT / "deploy" / "publish-github.sh"
    if not pub_path.exists():
        return
    assert ".gitleaks.toml" in pub_path.read_text(encoding="utf-8"), \
        ".gitleaks.toml not in publish allow-list"


# ── multi-user login + admin pages (1.1.0) ────────────────────────────────────
def test_login_and_admin_pages_exist():
    for f in ("login.html", "admin.html"):
        assert (ROOT / "web" / f).exists(), f"missing {f}"


def test_auth_pages_are_csp_safe():
    # nonce-based CSP forbids inline event handlers; both new pages must use
    # addEventListener only (no on*="..." attributes), like the dashboards.
    for f in ("login.html", "admin.html"):
        html = (ROOT / "web" / f).read_text(encoding="utf-8")
        assert not re.search(r'<[^>]+\son(click|input|change|submit|load|mouse\w+)=',
                             html), f"{f} has an inline event handler"


def test_admin_page_builds_dom_without_innerhtml():
    # the admin user table is built from JSON; it must use DOM APIs (textContent),
    # never innerHTML, so untrusted user fields (name/email) can't inject markup.
    html = (ROOT / "web" / "admin.html").read_text(encoding="utf-8")
    assert "innerHTML" not in html
    assert "createElement" in html and "textContent" in html
    assert "X-CSRF-Token" in html            # CSRF header on writes


def test_login_form_posts_to_login():
    html = (ROOT / "web" / "login.html").read_text(encoding="utf-8")
    assert 'action="/login"' in html
    assert 'method="post"' in html.lower()
    assert 'name="username"' in html and 'name="password"' in html


def test_admin_page_has_audit_log_section():
    html = (ROOT / "web" / "admin.html").read_text(encoding="utf-8")
    assert 'id="audit-rows"' in html and "loadAudit" in html
    assert "/api/admin/audit" in html
    assert "innerHTML" not in html          # still DOM-API only (XSS-safe)


def test_admin_page_has_profile_editor():
    # inline "Edit" per user → change email + role via the update action
    html = (ROOT / "web" / "admin.html").read_text(encoding="utf-8")
    assert "beginEdit" in html and '"Edit"' in html
    assert 'action:"update"' in html
    assert "innerHTML" not in html          # editor built with DOM APIs, not innerHTML


def test_admin_reset_pending_has_cancel_button():
    """A 'reset pending' user shows a Cancel button next to the message that lifts the
    forced-reset requirement (clear_reset action). Built with DOM APIs."""
    html = (ROOT / "web" / "admin.html").read_text(encoding="utf-8")
    assert "reset pending" in html
    # cancel control is wired to the clear_reset admin action, next to the pill
    assert 'action:"clear_reset"' in html
    assert "must_change_pw" in html and "Cancel" in html


# ============================================================================
# Leak / publish regression — encodes the manual sensitive-data sweep so a future
# edit can't silently push internal infra or a real secret to the public repo.
# Skips cleanly where the publisher isn't checked out (public tree / in-image gate).
# ============================================================================
# Markers of internal infrastructure that must never reach the public GitHub repo.
# The real values live in tests/_internal_markers.py, which is NOT in the publish
# ALLOW-list — so the names themselves never ship. Public checkout → import fails
# → the guard test skips (there is nothing to leak there anyway).
try:
    from _internal_markers import MARKERS as _INTERNAL_MARKERS
except ImportError:
    _INTERNAL_MARKERS = None


def _publish_allow_list():
    """Parse the ALLOW=(...) array from deploy/publish-github.sh — the exact set of
    files that ship to the public repo. Returns None when the publisher isn't in
    this checkout (the public repo / Docker test stage exclude it)."""
    pub = ROOT / "deploy" / "publish-github.sh"
    if not pub.exists():
        return None
    m = re.search(r'\nALLOW=\((.*?)\n\)', pub.read_text(encoding="utf-8"), re.S)
    assert m, "ALLOW=(...) array not found in publish-github.sh"
    return [t for t in m.group(1).split() if t and not t.startswith("#")]


def test_regression_env_and_publisher_excluded_from_public_repo():
    """.env (live secrets) is gitignored and never allow-listed; the publisher and
    the internal rules.md are declared PRIVATE_FILES, not published."""
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gi
    allow = _publish_allow_list()
    if allow is None:
        return
    assert ".env" not in allow
    assert "deploy/publish-github.sh" not in allow
    assert "rules.md" not in allow
    pub = (ROOT / "deploy" / "publish-github.sh").read_text(encoding="utf-8")
    pm = re.search(r'PRIVATE_FILES=\((.*?)\n\)', pub, re.S)
    assert pm and "publish-github.sh" in pm.group(1) and "rules.md" in pm.group(1)


def test_regression_no_internal_markers_in_published_files():
    """Every ALLOW-listed source/doc file is scanned for internal infra markers
    (private SSH alias, internal-domain hosts, engagement domains, RFC1918 lab IPs).
    tests/ are excluded (fixtures legitimately reference these; .gitleaks.toml
    allowlists them too), as are binaries and vendored JS assets."""
    allow = _publish_allow_list()
    if allow is None or _INTERNAL_MARKERS is None:
        return                       # public checkout: nothing to scan for / with
    # NB: tests/ are NOT skipped here — a marker (a private SSH remote alias) once
    # leaked via a test docstring, so published test files are scanned too. Fixture
    # marker literals live in tests/_internal_markers.py, not in the ALLOW-list.
    skip_ext = (".png", ".svg", ".ico", ".js")
    for rel in allow:
        p = ROOT / rel
        if not p.exists() or p.suffix.lower() in skip_ext:
            continue
        txt = p.read_text(encoding="utf-8", errors="ignore")
        for mark in _INTERNAL_MARKERS:
            assert mark not in txt, \
                f"internal marker {mark!r} leaked into published file {rel}"


def test_regression_no_real_secret_values_in_published_files():
    """No real-looking sk- key in any ALLOW-listed source file — only the known
    placeholders (CHANGE_ME / demo / supersecret / sk-... / proj-) are allowed."""
    allow = _publish_allow_list()
    if allow is None:
        return
    real_sk = re.compile(r'sk-[A-Za-z0-9]{16,}')
    placeholder = re.compile(r'sk-(CHANGE_ME|demo|supersecret|\.\.\.|proj-)')
    for rel in allow:
        if rel.startswith("tests/"):
            continue
        p = ROOT / rel
        if not p.exists() or p.suffix.lower() in (".png", ".svg", ".ico"):
            continue
        for hit in real_sk.findall(p.read_text(encoding="utf-8", errors="ignore")):
            assert placeholder.match(hit), \
                f"real-looking key {hit!r} in published file {rel}"


def test_regression_demo_seed_uses_synthetic_keys_only():
    """The committed dashboard screenshots are generated by scripts/demo_seed.py;
    its LiteLLM key values must be synthetic (sk-... / sk-demo), so a PNG can never
    bake in a real key."""
    seed = (ROOT / "scripts" / "demo_seed.py").read_text(encoding="utf-8")
    placeholder = re.compile(r'sk-(demo|\.\.\.|CHANGE_ME)')
    for hit in re.findall(r'sk-[A-Za-z0-9]{16,}', seed):
        assert placeholder.match(hit), f"demo_seed embeds a real-looking key: {hit!r}"
    assert "langgraph-agent" in seed        # synthetic aliases seen in the screenshots


def test_regression_gitleaks_runs_as_binary_not_node_action():
    """Regression for the Node 20 deprecation fix: gitleaks runs from the release
    binary (marketplace Node action removed), still alongside TruffleHog, still
    reading the repo .gitleaks.toml over full history."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "gitleaks/gitleaks-action" not in ci            # Node 20 action gone
    assert "gitleaks git . --config .gitleaks.toml" in ci  # binary invocation
    assert "trufflesecurity/trufflehog" in ci              # both scanners retained


def test_account_page_change_password_form():
    html = (ROOT / "web" / "account.html").read_text(encoding="utf-8")
    assert 'name="current"' in html and 'name="new"' in html      # requires current pw
    assert "/api/account/password" in html and "/api/me" in html
    assert "X-CSRF-Token" in html and "innerHTML" not in html      # CSRF + DOM-safe
    assert not re.search(r'<[^>]+\son(click|submit|change)=', html)  # no inline handlers


def test_account_page_has_webhook_section():
    html = (ROOT / "web" / "account.html").read_text(encoding="utf-8")
    assert 'id="wh-form"' in html and 'id="whurl"' in html and 'id="wh-test"' in html
    assert "/api/account/webhook" in html
    assert "innerHTML" not in html                       # DOM-API only
    assert not re.search(r'<[^>]+\son(click|submit|change)=', html)  # no inline handlers


# ── Prometheus /metrics + Kubernetes/fleet (1.3.0) ────────────────────────────
def test_prometheus_metrics_wired():
    assert (ROOT / "metrics_prom.py").exists()
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert 'add_get("/metrics"' in src and "metrics_prom.render" in src
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "MONITOR_METRICS_ENABLED" in env and "MONITOR_METRICS_TOKEN" in env
    # metric names are valid Prometheus identifiers, gauge families
    mp = (ROOT / "metrics_prom.py").read_text(encoding="utf-8")
    assert "aimon_up" in mp and "aimon_backend_up" in mp and "# TYPE" in mp


def test_k8s_and_helm_and_grafana_shipped():
    import json
    for f in ("deploy/k8s/ai-monitoring.yaml", "deploy/k8s/daemonset.yaml",
              "deploy/helm/ai-monitoring/Chart.yaml",
              "deploy/helm/ai-monitoring/values.yaml",
              "deploy/helm/ai-monitoring/templates/workload.yaml",
              "deploy/grafana/ai-monitoring-dashboard.json"):
        assert (ROOT / f).exists(), f"missing {f}"
    k8s = (ROOT / "deploy" / "k8s" / "ai-monitoring.yaml").read_text(encoding="utf-8")
    for kind in ("kind: Namespace", "kind: Deployment", "kind: Service",
                 "kind: ServiceMonitor"):
        assert kind in k8s, kind
    assert "/metrics" in k8s and "MONITOR_METRICS_TOKEN" in k8s
    # secrets in the shipped manifest are placeholders only
    assert "CHANGE_ME" in k8s
    dash = json.loads((ROOT / "deploy" / "grafana" / "ai-monitoring-dashboard.json").read_text(encoding="utf-8"))
    assert dash["panels"] and any(
        "aimon_" in str(t.get("expr", "")) for p in dash["panels"] for t in p.get("targets", []))


def test_deploy_artifacts_in_publish_allow_list():
    allow = _publish_allow_list()
    if allow is None:
        return
    for f in ("deploy/k8s/ai-monitoring.yaml",
              "deploy/helm/ai-monitoring/Chart.yaml",
              "deploy/grafana/ai-monitoring-dashboard.json", "metrics_prom.py"):
        assert f in allow, f"{f} not in publish ALLOW-list"


def test_prometheus_example_stack_shipped():
    base = ROOT / "deploy" / "prometheus-example"
    for f in ("docker-compose.yml", "prometheus.yml", "README.md",
              "grafana/provisioning/datasources/prometheus.yml",
              "grafana/provisioning/dashboards/dashboards.yml"):
        assert (base / f).exists(), f"missing prometheus-example/{f}"
    compose = (base / "docker-compose.yml").read_text(encoding="utf-8")
    assert "prom/prometheus" in compose and "grafana/grafana" in compose
    assert "MONITOR_METRICS_TOKEN" in compose
    prom = (base / "prometheus.yml").read_text(encoding="utf-8")
    assert "/metrics" in prom and "ai-monitoring:9925" in prom
    # demo tokens are placeholders only
    assert "CHANGE_ME" in compose and "CHANGE_ME" in prom
    # shipped + publishable
    allow = _publish_allow_list()
    if allow is not None:
        assert "deploy/prometheus-example/docker-compose.yml" in allow
