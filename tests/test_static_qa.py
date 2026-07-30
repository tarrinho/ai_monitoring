# Static QA — source inspection, no network/runtime backends required.
# Enforces the rules.md invariants that apply to this project: env-only
# secrets, dashboard security (§17), version consistency (§0a), fail-fast
# config, and container hardening.
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import config

ROOT = Path(__file__).resolve().parent.parent


def _core_js():
    """The shared self-hosted core module (aimon-core.js) that every page loads via a
    <script src>. The runtime harnesses collect only inline <script> blocks, so they must
    prepend this or api() (extracted there, review D-3) is undefined at runtime."""
    return (ROOT / "web" / "assets" / "aimon-core.js").read_text(encoding="utf-8")
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
    # every dashboard with a time-window selector also has ◀ / ▶ pan arrows.
    # spend joined the set: it loads aimon-core and pans via the shared api() `end=` append.
    for name in ("index", "litellm", "gpu", "ollama", "llamacpp", "spend"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'id="nav-left"' in html and 'id="nav-right"' in html, name
        assert "TIMEEND" in html and "/assets/aimon-core.js" in html, name   # panned query via shared api()
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


def test_litellm_per_model_shows_param_size():
    """The Per-model card shows each model's parameter count, inferred from the model name
    (LiteLLM does not report it). A `params` column + a `paramSize()` helper, and the header
    documents that it is inferred. Runs the REAL helper via node to guard the regex against
    false positives (version numbers like 3.5, 'mini', embeddings) and MoE/million forms."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert "function paramSize(" in html, "paramSize helper missing"
    assert ">params<" in html, "Per-model table missing a params column header"
    assert "inferred from the model name" in html, "params column must note it is inferred"
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    m = re.search(r"function paramSize\(name\)\{[\s\S]*?\n\}", html)
    assert m, "paramSize body not found"
    cases = {
        "qwen2.5-7b-instruct": "7B", "llama-3.3-70b": "70B", "mixtral-8x7b": "8×7B",
        "gemma-3-270m": "270M", "llama-3.1-405b": "405B", "qwen-1.5-72b-chat": "72B",
        "deepseek-r1-1.5b": "1.5B", "e5-mistral-7b": "7B",
        # no size token / must NOT false-match a version or 'mini'
        "phi-3.5": None, "gpt-5-mini": None, "gpt-4o-mini": None,
        "claude-3-5-sonnet": None, "text-embedding-3-large": None,
    }
    script = m.group(0) + "\nconsole.log(JSON.stringify([" + \
        ",".join(f"paramSize({n!r})" for n in cases) + "]));"
    out = subprocess.run([node, "-e", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    for (name, expect), val in zip(cases.items(), got):
        assert val == expect, f"paramSize({name!r}) = {val!r}, expected {expect!r}"


def test_network_total_follows_time_window():
    """The network 'Total down/up' KPIs must reflect bytes moved DURING the selected window
    (integrated from the rate series), not the cumulative-since-boot counter. Guards the
    wiring (windowBytes + _winDown/_winUp fed into the KPIs with an 'in <WIN>' sub) and runs
    the real integrator via node (constant rate over a window = rate × duration)."""
    net = ROOT / "web" / "network.html"
    if not net.exists():
        pytest.skip("network dashboard not present")
    html = net.read_text(encoding="utf-8")
    assert "function windowBytes(" in html, "windowBytes integrator missing"
    # the totals are fed from the windowed values, not net.rx_bytes_total (boot counter)
    assert 'kpi("Total down", _winDown' in html and 'kpi("Total up", _winUp' in html, \
        "Total down/up must use the windowed values"
    assert 'humanBytes(net.rx_bytes_total)' not in html, \
        "Total KPIs must no longer use the cumulative-since-boot counter"
    assert '"in "+WIN' in html, "windowed totals should note the active window"
    assert '_winDown=windowBytes(pts,"net_down")' in html and '_winUp=windowBytes(pts,"net_up")' in html
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    m = re.search(r"function windowBytes\(pts,key\)\{[\s\S]*?\n\}", html)
    assert m, "windowBytes body not found"
    script = m.group(0) + """
const P=[]; for(let t=0;t<=3600;t+=60) P.push({t, r:1000});   // 1000 B/s across 1h
const ramp=[{t:0,r:0},{t:100,r:100}];                          // trapezoid 0..100 over 100s
console.log(JSON.stringify([
  windowBytes(P,"r"),                    // 3,600,000
  windowBytes(ramp,"r"),                 // 5,000
  windowBytes([{t:0,r:null},{t:60,r:null}],"r"),   // null
  windowBytes([],"r")                    // null
]));"""
    out = subprocess.run([node, "-e", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == [3600000, 5000, None, None]


def test_network_scope_badge_shows_host_vs_container():
    """The network Live card must surface whether the figures are the HOST's NICs or only
    this container's netns — a `l-scope` badge fed from the collector's `net.scope`, with the
    'container' case telling the operator to set `pid: host`. Prevents Docker-bridge traffic
    from being silently mistaken for the host's network (the reported confusion)."""
    net = ROOT / "web" / "network.html"
    if not net.exists():
        pytest.skip("network dashboard not present")
    html = net.read_text(encoding="utf-8")
    assert 'id="l-scope"' in html, "network Live card missing the scope badge element"
    assert 'net.scope==="container"' in html and 'net.scope==="host"' in html, \
        "scope badge must handle both host and container states"
    assert "pid: host" in html, "container-scope state must tell the operator to set pid: host"
    # the collector actually emits the scope this UI consumes
    coll = (ROOT / "collectors" / "network.py").read_text(encoding="utf-8")
    assert '"scope"' in coll and '"host"' in coll and '"container"' in coll, \
        "network collector must emit a host/container scope for the badge"


def test_litellm_has_window_delta_key_chart():
    # new "requests in window" (delta) bar chart alongside the over-time keys chart
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert 'id="keydelta-chart"' in html
    assert "/api/keydelta" in html and "loadKeyDelta" in html and "keyDeltaChart" in html
    # it is a timeline (line chart plotting per-interval points), not a bar
    assert 'type:"line"' in html and "d.points" in html


def test_spend_all_charts_follow_time_window():
    """Every chart on the Spend page must follow the page time-window (SPWIN): the four
    time-series charts already did, and Cost-by-user/key/team now does too via a windowed
    per-key cost map (winSpent / /api/spend/keycost) reloaded on window change — so it no
    longer shows LiteLLM's all-time per-key total regardless of the selector."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    # the windowed cost source + helper
    assert "/api/spend/keycost?window=" in html and "function winSpent(" in html
    # cost-by chart uses the windowed spend, and re-fetches when the window changes
    assert "const spentOf=winSpent" in html
    m = re.search(r'#sp-windows button\[data-w\]"\)\.forEach.*?loadKeyCost\(\)', html, re.S)
    assert m, "window change must reload the windowed cost-by chart (loadKeyCost)"
    # each time-series chart still follows SPWIN
    for fn in ("loadSpendSeries", "loadModelCostSeries", "loadModelUserCostSeries"):
        assert f"{fn}()" in html
        assert re.search(rf"{fn}.*?window=\"?\+?SPWIN", html, re.S), f"{fn} must use SPWIN"


def test_litellm_concurrency_backlog_by_key_stacked_and_labeled_estimated():
    """The two stacked charts (Concurrent work / Backlog) exist, read the attribution endpoint,
    follow the window, and are HONESTLY labeled as estimated — LiteLLM gives no per-key
    breakdown for these aggregates (the split is inferred). They are titled 'by user', so the
    server's per-key bands are folded to OWNERS before rendering (a 'by user' chart must never
    show a raw key id — see test_by_user_charts_never_show_a_key_id)."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    for cid in ("card-conc-by-key", "card-backlog-by-key",
                "conc-by-key-chart", "backlog-by-key-chart"):
        assert cid in html, f"missing {cid}"
    assert "/api/litellm/concurrency-by-key" in html
    assert "loadConcByKey" in html and "loadBacklogByKey" in html
    # titled "by user" → both loaders must fold the per-key server bands to users, so a key id
    # can never surface under a "by user" heading (regression guard for the exact bug fixed).
    assert re.search(r"<h2>Concurrent LLM work — by user", html), "conc card must be titled 'by user'"
    assert re.search(r"<h2>LLM Backlog — by user", html), "backlog card must be titled 'by user'"
    for fn in ("loadConcByKey", "loadBacklogByKey"):
        m = re.search(r"async function " + fn + r"\(\)\{.*?\n\}", html, re.S)
        assert m and "_foldSeriesByUser(d.series)" in m.group(0), \
            f"{fn} must fold per-key bands to users (else a 'by user' chart shows key ids)"
    # both reload on window change / tick (search for them in rangedReload)
    assert re.search(r"function rangedReload\(\)\{[^}]*loadConcByKey\(\)[^}]*loadBacklogByKey\(\)", html)
    # stacked area (bands sum to the total) and the "estimated" honesty must be present
    assert "stacked:true" in html
    # Same fill-to-origin defect as bug-registry class #1 (gpu.html's per-app CPU stack):
    # fill:true fills every dataset to the zero axis, so translucent bands stack on top of
    # each other and blend together instead of reading as a clean stack. Scoped to
    # renderStackByKey so this can't hide behind an unrelated chart's correct occurrence.
    m = re.search(r"function renderStackByKey\(.*?\n\}", html, re.S)
    assert m, "renderStackByKey not found"
    assert re.search(r'fill:\s*i\s*\?\s*["\']-1["\']\s*:\s*["\']origin["\']', m.group(0)), \
        "by-key stacked charts must fill to previous dataset, not to zero"
    assert "fill:true" not in m.group(0), \
        "by-key stacked charts regressed to filling every band to the zero axis"
    assert "Estimated attribution" in html and "no per-key breakdown" in html


def test_litellm_keytime_is_cumulative_requests_not_rolling():
    """'Top 10 API keys over time' plots CUMULATIVE requests (all-time, only rises) from the
    daily rollup — NOT the rolling 15-min request count that decays to 0 when a key goes
    quiet (the reported "why did the number drop" confusion). Guards the rewire so it can't
    regress to the falling rolling-window series."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert "/api/keyrequests" in html, "keytime chart must read the cumulative-requests endpoint"
    assert "cumulative requests" in html and "all time" in html, "header/labels must say all-time cumulative"
    # loadKeyTime must no longer pull the rolling per-window key request series
    m = re.search(r"async function loadKeyTime\(\)\{.*?\n\}", html, re.S)
    assert m, "loadKeyTime not found"
    assert "/api/keyseries" not in m.group(0), "keytime must not use the rolling keyseries"
    assert "rolling window" not in m.group(0), "the falling rolling-window note must be gone"


def test_per_model_table_has_vertical_column_dividers():
    """The Per-model table (#ll-models) has five right-aligned numeric columns (params · reqs ·
    tokens · svc CPU · svc RAM) that blur together with only horizontal row lines — a value
    couldn't be tied to its header. Scoped vertical column dividers fix the association."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert re.search(r"#ll-models table th,\s*#ll-models table td\{[^}]*border-left:", html), \
        "Per-model table must have vertical column dividers (border-left on its cells)"
    # the first column is exempt so there's no dangling divider on the left edge
    assert re.search(r"#ll-models table th:first-child,\s*#ll-models table td:first-child\{"
                     r"[^}]*border-left:\s*none", html)


def test_per_model_svc_cpu_ram_covers_vllm_sglang_tgi():
    """svc CPU/RAM on the Per-model table maps a model's backend to its serving process. vLLM /
    SGLang / TGI (relabelled by the procs collector) must be covered — previously only llama.cpp
    + ollama were, so a vLLM-served model always showed '—'. The 'LLM serving …' over-time
    charts filter the same server set."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    m = re.search(r"function svcProc\(backend\)\{.*?\n\}", html, re.S)
    assert m, "svcProc not found"
    body = m.group(0)
    for b in ("vllm", "sglang", "tgi"):
        assert f'backend==="{b}"' in body, f"svcProc must map the {b} backend to a process name"
    # the two 'LLM serving …' charts filter the same expanded server set
    assert html.count("/llama|ollama|vllm|sglang|tgi/i") == 2
    # both svc columns carry a hover tooltip explaining what they are (they used to be bare)
    assert '<th class="num" title="Serving-process CPU' in html, "svc CPU header needs a tooltip"
    assert '<th class="num" title="Serving-process RAM' in html, "svc RAM header needs a tooltip"


def test_litellm_has_per_user_usage_charts():
    """The keys usage charts (bar 'by requests' + delta 'requests in window') each
    have a per-USER sibling that aggregates keys by owner client-side, using the
    alias→owner map built from /api/budgets (keys with no owner fall back to the key)."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    # the two new cards + their canvases
    assert 'id="card-userkeys"' in html and 'id="user-keys-chart"' in html
    assert 'id="card-userdelta"' in html and 'id="userdelta-chart"' in html
    assert "Top 10 API users by requests" in html
    # the delta card's metric word is now a span filled by labelDeltaCard() — it reads
    # "requests" in full mode and "spend" in lite (where per-key request counts don't
    # exist), so anchor on the surrounding markup rather than one contiguous string.
    assert re.search(r'Top 10 API users — <span id="userdelta-metric">requests</span> in window',
                     html), "user delta heading lost its metric span"
    # the aggregation wiring: owner map from budgets + the two render/load funcs
    assert "buildKeyUser" in html and "_keyUser" in html and "userOf(" in html
    assert "renderUserKeys" in html and "userKeysChart" in html
    assert "loadUserDelta" in html and "userDeltaChart" in html
    # user-delta reuses the keydelta endpoint and is refreshed on window change/pan
    assert html.count("loadUserDelta(") >= 3   # def + rangedReload + window handler


def test_litellm_no_longer_has_the_budgets_card():
    """The 'Spend & Quota — per-key budgets' card was removed from /litellm — that view
    lives on the dedicated /spend page (its own card-keys section). The /api/budgets
    FETCH must survive, though: buildKeyUser() still needs it to build the alias→owner
    map the per-user usage charts (test above) depend on."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    for gone in ("card-budgets", "bud-badge", "bud-body", "loadBudgets", "per-key budgets"):
        assert gone not in html, f"{gone!r} should have been removed with the budgets card"
    # the underlying fetch + owner-map builder must remain — a different feature depends on it
    assert 'await api("/api/budgets")' in html
    assert "buildKeyUser(budgets)" in html


def test_windowed_pages_have_live_button():
    # a "Live" button jumps the window back to the current time (TIMEEND=null),
    # enabled only when panned into history.
    for name in ("index", "litellm", "gpu", "ollama", "llamacpp"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'id="nav-live"' in html, name
        # click handler snaps to live; disabled state tracks TIMEEND
        assert 'getElementById("nav-live").addEventListener' in html, name
        assert "TIMEEND=null; _winMark(false); _winSave(WIN, null); updateRangeUI()" in html, name
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
    assert config.VERSION == "AI-Monitoring_1.8.14"


def test_all_version_surfaces_match_config_version():
    """Regression for the version-drift blind spot: every image tag / chart version /
    sidebar badge across deploy manifests, compose files, the Helm chart, and the README
    offline-install snippet must equal config.VERSION — these lagged in past releases
    (deploy/k8s + prometheus-example + README were the repeat offenders). Derives the
    version from config so it can't go stale itself."""
    ver = config.VERSION.split("_", 1)[1]              # e.g. "1.8.8"
    other = re.compile(r"(?:ai[-_]monitoring|ai_monitoring):(\d+\.\d+\.\d+)")

    def stale_tags(text):
        return {m for m in other.findall(text) if m != ver}

    surfaces = [
        ROOT / "docker-compose.yml",
        ROOT / "deploy" / "docker-compose.server.yml",
        ROOT / "deploy" / "k8s" / "ai-monitoring.yaml",
        ROOT / "deploy" / "k8s" / "daemonset.yaml",
        ROOT / "deploy" / "prometheus-example" / "docker-compose.yml",
        ROOT / "deploy" / "prometheus-example" / "README.md",
        ROOT / "README.md",
    ]
    for p in surfaces:
        if not p.exists():
            continue
        bad = stale_tags(p.read_text(encoding="utf-8"))
        assert not bad, f"{p.relative_to(ROOT)}: stale image tag(s) {bad}, expected {ver}"

    # Helm chart version + appVersion
    chart = ROOT / "deploy" / "helm" / "ai-monitoring" / "Chart.yaml"
    if chart.exists():
        c = chart.read_text(encoding="utf-8")
        assert re.search(rf'(?m)^version:\s*{re.escape(ver)}\b', c), "Helm chart version stale"
        assert re.search(rf'(?m)^appVersion:\s*"{re.escape(ver)}"', c), "Helm appVersion stale"

    # every dashboard's sidebar badge reads the same vX.Y.Z
    for pg in (ROOT / "web").glob("*.html"):
        for m in re.findall(r'sidebar-brand-ver">v(\d+\.\d+\.\d+)', pg.read_text(encoding="utf-8")):
            assert m == ver, f"{pg.name}: sidebar-brand-ver v{m} != {ver}"


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


def test_freshness_indicator_shared_and_not_client_clock():
    """Review-fix (F2): the /spend and /alerts 'updated' indicators used the CLIENT wall-clock
    (`new Date().toLocaleTimeString()`), which advances every poll even when the data is stale —
    an actively misleading 'fresh' signal on the cost page. They now use the shared aimon-core
    `paintUpdated(elId, lastOkMs)` helper, which ages green→amber→red from the last SUCCESSFUL
    update so a frozen/erroring page visibly goes stale."""
    core = (ROOT / "web" / "assets" / "aimon-core.js").read_text(encoding="utf-8")
    assert "function paintUpdated(" in core, "shared paintUpdated helper missing"
    for page in ("spend.html", "alerts.html"):
        html = (ROOT / "web" / page).read_text(encoding="utf-8")
        assert 'paintUpdated("updated"' in html, f"{page} must use the shared freshness helper"
        assert '"updated "+new Date().toLocaleTimeString()' not in html, \
            f"{page} still shows the misleading client-clock 'updated' time"
    # alerts: the freshness stamp must be GATED on a successful poll (`_lastAlertCheck`, inside
    # the if(d) block) — the earlier unconditional `_lastAlertCheck || 0` form masked api()'s
    # explicit "disconnected"/"auth-error" status on a failed poll. Guard against that regression.
    alerts = (ROOT / "web" / "alerts.html").read_text(encoding="utf-8")
    assert 'paintUpdated("updated", _lastAlertCheck)' in alerts
    assert 'paintUpdated("updated", _lastAlertCheck || 0)' not in alerts, \
        "alerts freshness must be gated on success, not overwrite the error status"


def test_collapsible_section_headers_are_keyboard_accessible():
    """Review-fix (F3): the collapsible chart-section headers were plain <div>s with only a click
    handler — not focusable, no Enter/Space. index.html now wires them through the shared
    aimon-core `a11yToggle` (role=button + tabindex + keydown) and keeps aria-expanded in sync."""
    core = (ROOT / "web" / "assets" / "aimon-core.js").read_text(encoding="utf-8")
    assert "function a11yToggle(" in core and 'setAttribute("role","button")' in core
    assert 'ev.key!=="Enter"' in core and 'ev.key!==" "' in core, "a11yToggle must handle Enter/Space"
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert "a11yToggle(hd" in html, "index.html collapse header must use a11yToggle"
    assert 'aria-expanded' in html


def test_index_sse_has_data_starvation_watchdog():
    """Review-fix: index.html's SSE path must not suppress the /api/data poll FOREVER on a
    half-open stream that stays connected but stops delivering (no es.onerror fires). A watchdog
    stamps each message time (`_lastSse`) and resumes polling when no message arrived recently,
    so the page can't silently freeze while still looking 'connected'."""
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert "_lastSse" in html, "SSE data-starvation watchdog (_lastSse) missing"
    assert "es.onmessage" in html and "_lastSse=Date.now()" in html, "onmessage must stamp _lastSse"
    assert "Date.now()-_lastSse" in html, "tick() must gate SSE-covers-poll on message freshness"


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


def test_per_model_table_does_not_blink_on_transient_miss():
    """Regression: the /litellm Per-model table blinked (whole table blanked + redrawn every 5s)
    because loadModels() full-`setHtml`-rebuilt it each poll AND wiped it to an 'unavailable'
    placeholder whenever a backend flapped down (e.g. vLLM restarting). It must (a) keep the
    last-good table on a transient miss — only show the placeholder before the FIRST load — and
    (b) rebuild the DOM only when the STRUCTURE changes, updating live number cells in place."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert "_pmHas" in html and "_pmSig" in html, "per-model anti-blink state missing"
    # the unavailable / empty branches must be gated on _pmHas (don't wipe a shown table)
    assert "if(!_pmHas) setHtml(el,`<div class=\"unavail\">LiteLLM not configured" in html
    assert "if(sig===_pmSig && _pmHas)" in html, "must skip rebuild when structure is unchanged"
    # live number cells are updated in place (ids), not via a full setHtml each tick
    assert 'id="pmscpu' in html and 'id="pmsram' in html and 'id="pmreq' in html


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
    # The serving-process filter must recognize vLLM (process names "vllm" /
    # "VLLM::EngineCor"), not just llama.cpp/Ollama — a GB10 box running vLLM
    # as its local backend previously left both over-time charts permanently
    # empty because the filter regex only matched llama|ollama (bug-registry #7).
    # Intent-based (not an exact-string count) so extending the alternation with
    # further self-hosted servers — e.g. sglang/tgi — can't regress this guard: both
    # filter sites (_svcDatasets + loadImpact's align) must still include vllm.
    svc_filters = re.findall(r'/([a-z|]+)/i\.test\(a\)', html)
    assert len(svc_filters) == 2, (
        f"expected two serving-process filter sites, found {len(svc_filters)}: {svc_filters}")
    for pat in svc_filters:
        parts = pat.split("|")
        assert {"llama", "ollama", "vllm"} <= set(parts), (
            f"serving-process filter {pat!r} must include llama+ollama+vllm (not regress to llama-only)")
    # per-model resource cost columns sourced from the procs collector
    assert "svcProc" in html and "svc CPU" in html and "svc RAM" in html
    assert 'type:"bar"' in html
    # top-10 keys OVER TIME — multi-line, one color per key; cumulative all-time spend
    assert 'id="keytime-chart"' in html and "loadKeyTime" in html
    assert "/api/keyrequests" in html and "KEY_COLORS" in html
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
    # the per-run boot smoke check must find no STRUCTURAL problem in a healthy checkout.
    # The open-mode advisory is a config warning about THIS env (test config runs tokenless
    # on 0.0.0.0), not a checkout defect — filter it so the structural intent stays exact.
    import app
    problems = [p for p in app.startup_selfcheck() if "OPEN MODE" not in p]
    assert problems == []


def test_dockerfile_gates_build_on_tests():
    # QA must run on every build: a `test` stage runs pytest and the runtime
    # stage depends on its marker, so a regression fails `docker build`.
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "AS test" in df and "pytest" in df
    assert "COPY --from=test /qa-passed" in df


def test_runtime_image_strips_pip():
    """Image-CVE hygiene: the RUNTIME stage removes pip. The app never installs packages at
    runtime, and pip's vendored deps otherwise surface as image-scan HIGHs (pip 26.2 vendors
    setuptools 70.3.0 → CVE-2025-47273 and msgpack 1.1.2 → GHSA-6v7p-g79w-8964). Stripping pip
    keeps Trivy green on every rebuild regardless of which pip the base image ships."""
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "AS runtime" in df
    runtime = df[df.index("AS runtime"):]            # only the runtime stage
    assert "rm -rf" in runtime and "site-packages/pip" in runtime, \
        "runtime stage must strip pip (unused at runtime; its vendored deps flag as CVEs)"


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
    # guard: EVERY top-level .py the app ships must be COPYed into the runtime image, or the
    # container crashes on import. Derived from the tree (not a hand-list) so a newly-extracted
    # module — e.g. dbutil.py (review D-4) — can't be forgotten in the Dockerfile.
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    mods = {p.name for p in ROOT.glob("*.py")
            if p.name not in ("conftest.py", "setup.py")}
    assert "dbutil.py" in mods, "sanity: dbutil.py should be a top-level module"
    for mod in sorted(mods):
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


def test_vllm_kpis_use_class_arg_not_embedded_markup():
    """Regression: the vLLM KPI values (Waiting/Swapped/Preemptions) used to embed a
    `<span class="c-warn">` inside kpi(), whose `escapeHtml(val)` then rendered the tag as
    literal text ('<span class="">0…'). kpi() takes a class arg and the callers pass a bare
    value, so the number shows and the warn colour is applied via a styled `.v.warn`."""
    html = (ROOT / "web" / "vllm.html").read_text(encoding="utf-8")
    assert "function kpi(label,val,cls)" in html, "kpi() must accept a class arg"
    assert re.search(r"<div class=\"v \$\{cls\|\|\"\"\}\">", html), "kpi() must apply cls to .v"
    assert "kpi(\"Waiting\", wait!=null?wait:\"—\", warnWait?\"warn\":\"\")" in html
    # no KPI call embeds raw span markup that escapeHtml would leak as text
    assert not re.search(r'kpi\([^)]*<span', html), "kpi() must not receive <span> markup"
    # the warn class it applies is actually styled
    assert ".kpi .v.warn{color:var(--warn)}" in html


def test_no_kpi_value_embeds_raw_span_markup():
    """Regression (llamacpp CPU-threads, vLLM Waiting/Swapped/Preemptions): a value passed
    to kpi() must NOT embed `<span>` markup — kpi() escapeHtml's its value, so the tag would
    render as literal text ('<span class="">…'). Colour/sub-label go through kpi()'s class /
    sub params (which escape their content) instead. Scans every dashboard's kpi() calls."""
    for fn in sorted((ROOT / "web").glob("*.html")):
        src = fn.read_text(encoding="utf-8")
        # drop the kpi() helper definition itself — it legitimately builds an escaped <span>
        src2 = re.sub(r"function kpi\(.*?\n\}", "", src, flags=re.S)
        for m in re.finditer(r"\bkpi\(", src2):
            seg = src2[m.start(): m.start() + 400]
            end = re.search(r"\+kpi\(|setHtml|\)\);", seg)
            arg = seg[: end.start()] if end else seg[:200]
            assert "<span" not in arg, \
                f"{fn.name}: kpi() value embeds <span> (would render as literal text): {arg[:80]!r}"


def test_vllm_every_graph_has_a_tooltip():
    """Every chart on the vLLM page must carry an info tooltip explaining its goal: each
    CHARTS entry has a `desc`, and the builder renders it as an `.info` element."""
    html = (ROOT / "web" / "vllm.html").read_text(encoding="utf-8")
    chart_ids = re.findall(r'\{id:"(c-[a-z0-9]+)"', html)
    assert len(chart_ids) >= 10, f"expected the full vLLM chart set, found {chart_ids}"
    # one desc per chart config
    assert html.count("desc:") >= len(chart_ids), "every CHARTS entry needs a desc"
    # the builder turns desc into an info element, and .info is styled
    assert 'info.className="info"' in html, "builder must render cfg.desc as an .info element"
    assert ".info{" in html, "vLLM page must style .info"
    # help opens on CLICK, not hover: no native title= tooltip on the icon, a click
    # handler on the trigger, and a dedicated popover element that carries the desc
    assert "info.title=cfg.desc" not in html, \
        "help must be click-toggled, not a hover-only title= tooltip"
    assert 'info.addEventListener("click"' in html, "info icon must toggle on click"
    assert "info-pop" in html and "closeAllInfo" in html, \
        "click help needs a popover element and an outside/Escape dismiss path"
    assert "pop.textContent=cfg.desc" in html, "the popover must carry the graph's desc"
    # accessible toggle state
    assert 'aria-expanded' in html


def test_backend_logos_are_published():
    """Every /assets/logos/*.svg the dashboards reference (nav mask-image, README row)
    must be in the publish ALLOW-list, or the publisher drops it and the shipped pages
    render broken icons. Regression for the logos-missing-from-ALLOW gap (rules §9a)."""
    referenced = set()
    for f in (ROOT / "web").glob("*.html"):
        referenced.update(re.findall(r"/assets/logos/([\w.-]+\.svg)", f.read_text(encoding="utf-8")))
    assert referenced, "expected at least one referenced backend logo"
    pub = ROOT / "deploy" / "publish-github.sh"
    if not pub.exists():           # publish script is not always vendored
        return
    allow = pub.read_text(encoding="utf-8")
    for svg in sorted(referenced):
        assert f"logos/{svg}" in allow, f"publish ALLOW-list missing web/assets/logos/{svg}"


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


def test_cost_over_time_reads_actual_cash_and_shows_lifetime():
    """The Cost over time card must present its REAL series as actual LiteLLM cash (not a
    'tokens × price' estimate) and expose a lifetime figure so it reconciles with per-key
    spend. Guards the anchor-to-actual relabelling + the lifetime line."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    # real series is actual cash — the misleading 'estimated' framing is gone
    assert '<h2>Cost over time</h2>' in html, "stale 'estimated' badge on the card title"
    assert 'estimated cost this year' not in html.lower()
    assert 'actual LiteLLM cash' in html
    # lifetime real is rendered from the server field so window/YTD totals don't look wrong
    assert 'real_cost_lifetime' in html
    assert 'lifetime real' in html
    # the note disambiguates the window total vs the year-to-date/lifetime box
    assert 'chart window' in html and 'year-to-date + lifetime' in html


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


def test_ruff_ruleset_is_explicit_not_the_moving_default():
    """CI installs ruff unpinned (`pip install ruff`), so `ruff check .` uses whatever ruff
    ships as its DEFAULT rule set. That default is not stable: ruff 0.16.0 broadened it to
    also enable BLE/S/I/PL/etc. (300+ new findings), reddening CI on a linter upgrade with no
    code change. Pin the intended rules EXPLICITLY in ruff.toml so lint is reproducible across
    ruff versions. (verified identical on 0.15.13 and 0.16.0.)"""
    cfg = (ROOT / "ruff.toml").read_text(encoding="utf-8")
    assert re.search(r'(?m)^\[lint\]\s*$', cfg), "ruff.toml must declare an explicit [lint] table"
    m = re.search(r'select\s*=\s*\[([^\]]*)\]', cfg)
    assert m, "ruff.toml [lint] must set an explicit `select` (else CI rides ruff's moving default)"
    sel = {s.strip().strip('\'"') for s in m.group(1).split(",") if s.strip()}
    assert {"E4", "E7", "E9", "F"} <= sel, \
        f"the explicit select must keep ruff's historical E/F default, got {sel}"


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


def test_demo_seed_theme_shim_stamps_the_csp_nonce():
    """F5's per-response CSP nonce (app.py) blocks any <script> tag without it. The theme
    shim injects its own <script> tags AFTER _orig_serve already nonce-stamped the page,
    so an un-stamped shim tag is silently dropped by CSP — the ?theme= query param then
    does nothing and every screenshot renders in the default (dark) theme regardless of
    what was requested. The shim must read the nonce _orig_serve already put in the
    response header and stamp its own tags with the same value."""
    src = (ROOT / "scripts" / "demo_seed.py").read_text(encoding="utf-8")
    assert "resp.headers.get(A._NONCE_HDR)" in src, \
        "shim must read the nonce _orig_serve already stamped into the response header"
    m = re.search(r"def _serve_with_theme\(.*?\n(?=def |\Z)", src, re.S)
    assert m, "_serve_with_theme not found"
    body = m.group(0)
    assert body.count("<script{nattr}>") >= 2, \
        "both injected <script> tags (theme setter + popover forcer) must carry the nonce"
    assert "<script>" not in body, \
        "an injected <script> tag without the nonce attribute is silently CSP-blocked"


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


def test_spend_model_user_cost_time_card():
    """Spend page carries the 'Cost per model & user over time' stacked-area card: its
    section + canvas, the window/mode/group toggles, a loader hitting the local-rollup
    endpoint, and the shared updateSeries helper (never a full datasets rebuild in the
    caller). Money rendered via CUR."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    assert 'id="card-model-user-cost-time"' in html
    assert 'id="model-user-cost-chart"' in html
    assert "/api/spend/model-user-series" in html
    assert "loadModelUserCostSeries" in html and "renderModelUserCostTime" in html
    assert "updateSeries(modelUserChart" in html          # in-place refresh, keep toggles
    # window is the page-level control (#sp-windows in the header, drives every chart);
    # the card keeps only its own display toggles
    assert 'id="mu-mode"' in html and 'id="mu-group"' in html
    assert "window=\"+SPWIN" in html                         # model×user follows the page window
    assert "stacked:true" in html                          # it's a STACKED area chart
    # Same fill-to-origin defect as bug-registry class #1 (gpu.html's per-app CPU stack):
    # fill:true fills every dataset to the zero axis, so translucent bands stack on top of
    # each other and blend together instead of reading as a clean stack.
    m = re.search(r"function renderModelUserCostTime\(.*?\n\}", html, re.S)
    assert m, "renderModelUserCostTime not found"
    assert re.search(r'fill:\s*i\s*\?\s*["\']-1["\']\s*:\s*["\']origin["\']', m.group(0)), \
        "model×user stacked chart must fill to previous dataset, not to zero"
    assert "fill:true" not in m.group(0), \
        "model×user stacked chart regressed to filling every band to the zero axis"
    # placed AFTER 'cost per model over time', BEFORE the per-key budgets table
    assert (html.index('id="card-model-cost-time"')
            < html.index('id="card-model-user-cost-time"')
            < html.index('id="card-keys"'))


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
    for f in ("spend.html", "litellm.html", "settings.html", "index.html",
              "alerts.html", "gpu.html", "vllm.html"):
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


def test_all_pages_have_consistent_time_window_with_mtd():
    """Every dashboard page carries the same header time-window control (15m/1h/24h/30d/
    12mo + month-to-date), a month-aware `wsecs` helper (no stale WSECS[WIN]), and the
    unified prettier pill styling."""
    HEADER_PAGES = ("index", "gpu", "ollama", "llamacpp", "litellm", "vllm")
    for name in HEADER_PAGES:
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        for w in ("15m", "1h", "24h", "30d", "12mo", "month"):
            assert f'data-w="{w}"' in html, f"{name}: missing window {w}"
        # month button labelled MTD (aria-pressed attr may sit between data-w and >)
        assert re.search(r'data-w="month"[^>]*>MTD', html), f"{name}: month button not labelled MTD"
        # a11y: window buttons are a select group — each carries aria-pressed so the
        # active window is announced, not signalled by colour alone; active one is "true".
        wbtns = re.findall(r'<button data-w="[^"]*"[^>]*>', html)
        assert wbtns and all("aria-pressed=" in b for b in wbtns), \
            f"{name}: window buttons missing aria-pressed"
        assert sum('aria-pressed="true"' in b for b in wbtns) == 1, \
            f"{name}: exactly one window button must be aria-pressed=true"
        # wsecs() now lives in the shared core module (review D-3), so every page must load it.
        assert "/assets/aimon-core.js" in html, f"{name}: does not load aimon-core.js"
        assert "WSECS[WIN]" not in html, f"{name}: stale WSECS[WIN] (not month-aware)"
        assert "unified time-window control" in html, f"{name}: missing unified pill styling"
    # The month-aware wsecs() helper is defined once, in the shared core module.
    core = (ROOT / "web" / "assets" / "aimon-core.js").read_text(encoding="utf-8")
    assert "function wsecs(" in core, "core: missing month-aware wsecs() helper"
    assert "getUTCMonth()" in core, "core: wsecs() no longer month-aware"
    # spend uses the same pill styling too (its windows are card-scoped / coarser)
    assert "unified time-window control" in (ROOT / "web" / "spend.html").read_text(encoding="utf-8")


def test_wire_legend_full_name_mutates_raw_config_not_resolved_proxy():
    """Regression (live incident 2026-07-28): wireLegendFullName() hard-hung EVERY dashboard at
    load. On Chart.js v4.4 assigning into the RESOLVED `chart.options.plugins.legend.*` proxy
    recurses infinitely (Object.set ↔ Object.set → RangeError / frozen page). It must mutate the
    RAW `chart.config.options` instead (the resolved options read through to it, so hover still
    works). The stub-based JS gate uses a fake Chart with plain options, so it can't catch this —
    this static check guards the invariant directly."""
    core = (ROOT / "web" / "assets" / "aimon-core.js").read_text(encoding="utf-8")
    body = core.split("function wireLegendFullName", 1)[1].split("\nfunction ", 1)[0]
    code = "\n".join(ln.split("//", 1)[0] for ln in body.splitlines())   # drop // comments
    assert "chart.config.options" in code, \
        "wireLegendFullName must mutate chart.config.options (raw), not the reactive chart.options proxy"
    assert "chart.options.plugins" not in code, \
        "wireLegendFullName must NOT touch chart.options.plugins (Chart.js v4 proxy recursion)"


def test_no_duplicate_windows_css_block():
    """Regression: the header time-window widget's CSS used to be defined twice per page
    (an old faint-active block + the newer solid-accent one), the first dead-overridden
    but its `margin-left` leaking. Exactly one `.windows{` selector per page now."""
    for name in ("gpu", "index", "litellm", "llamacpp", "ollama", "vllm", "spend"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert html.count(".windows{") == 1, f"{name}: duplicate/dead .windows CSS block"


def test_gpu_stacked_cpu_charts_normalized_to_100():
    """Both stacked CPU charts on the GPU/CPU page (per-app + per-core) express each band
    as a share of TOTAL capacity so the stack tops at 100%, not top-style per-process %CPU
    (relative to one core → could sum to cores×100). Guards the >100% regression: a fixed
    `max:100` axis, division by the core count, and a tooltip that recovers the raw load."""
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    # two stacked-area charts, both capped at 100%
    assert html.count("stacked:true,beginAtZero:true,max:100") == 2, \
        "both stacked CPU charts must pin the axis at max:100"
    # per-app chart divides each process %CPU by the core count (from ncpu)
    assert "_appCpuN=(d.ncpu&&d.ncpu>0)?d.ncpu:(_cpuCoreN>1?_cpuCoreN:1)" in html, \
        "per-app chart must derive its divisor from ncpu"
    assert "(p[a]==null?0:p[a])/n" in html, "per-app data must be divided by the core count"
    # per-core chart divides each core% by N so the N bands sum to the overall load
    assert "return (v==null?0:v)/n;" in html, "per-core bands must be core% ÷ N"
    # both tooltips recover the raw top-style load (band × cores) + show the share
    assert "c.parsed.y*_appCpuN" in html and "c.parsed.y*_cpuCoreN" in html, \
        "tooltips must recover raw load as band × cores"
    assert html.count('% of total)') >= 2, "tooltips must label the share as % of total"


def test_appcpu_info_tooltip_describes_normalization():
    """The per-app CPU card's info tooltip must explain the axis is normalized to % of
    total (not raw per-process %CPU) — else the 0–100 axis silently misleads."""
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    assert "normalized to % of TOTAL capacity" in html
    assert "band × cores" in html


def test_chart_canvases_are_labelled_for_screen_readers():
    """a11y: every static chart <canvas> exposes role=img + a text aria-label, so a
    screen reader announces what the (otherwise opaque) chart shows instead of nothing.
    Dynamically-built canvases get the same via cv.setAttribute in their JS builders."""
    for name in ("gpu", "index", "litellm", "spend"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        canvases = re.findall(r"<canvas[^>]*>", html)
        assert canvases, f"{name}: expected static canvases"
        for c in canvases:
            assert 'role="img"' in c and "aria-label=" in c, f"{name}: unlabelled canvas {c}"
    # JS chart builders label the canvases they create
    for name in ("gpu", "index", "litellm", "llamacpp", "ollama", "vllm"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'setAttribute("role","img")' in html or 'setAttribute("role", "img")' in html, \
            f"{name}: dynamic canvas builder must label its canvas"


def test_window_controls_are_grouped_and_labelled():
    """a11y/UX: the header time-window control is a labelled group (role=group), the
    icon-only pan buttons carry aria-labels (not title alone), and a visual divider
    (.wsep) separates the window selector from the live/pan cluster."""
    for name in ("gpu", "index", "litellm", "llamacpp", "ollama", "vllm", "spend"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'role="group"' in html, f"{name}: window control not a role=group"
        for btn in ("nav-left", "nav-right", "nav-live"):
            m = re.search(rf'<button id="{btn}"[^>]*>', html)
            assert m and "aria-label=" in m.group(0), f"{name}: {btn} missing aria-label"
        assert 'class="wsep"' in html and ".windows .wsep{" in html, \
            f"{name}: missing window/pan divider"


def test_usage_over_time_tokens_split_external_internal():
    """The Spend 'Usage over time' bar colours tokens by EXTERNAL (paid) vs INTERNAL
    (self-hosted): two stacked datasets, distinct colours, fed from tokens_ext/tokens_int
    with a graceful fallback to a single 'Tokens' bar when the split isn't available."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    assert "External tokens" in html and "Internal tokens" in html   # two datasets
    assert 'stack:"tok"' in html                                     # stacked into one bar
    assert "p.tokens_ext" in html and "p.tokens_int" in html         # fed from the split
    assert "d.tokens_split" in html                                  # gated on availability
    # distinct colours (external vs internal), not the same token colour
    assert 'backgroundColor:cssv("--accent")' in html and 'backgroundColor:cssv("--ok")' in html


def test_settings_hides_cards_for_absent_backends():
    """Settings shows only cards that make sense: config groups gate on the backend they
    need (GPU group → GPU present; LiteLLM group + Teams + Model-costs → LiteLLM present),
    read from the live collectors (nav.gpu is always true now). Default-present so a failed
    probe never hides real config."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    assert "function fetchPresence" in html and "function applyPresence" in html
    # group → backend map + the render-time filter that drops absent-backend groups
    assert 'GROUP_BACKEND={GPU:"gpu", LiteLLM:"litellm"}' in html
    assert "GROUP_BACKEND[s.group]" in html and "_present[b]!==false" in html
    # static LiteLLM cards removed when no LiteLLM; their loaders skipped
    assert '"teams-card","models-card"' in html
    assert "if(_present.litellm){ loadTeams(); loadModels(); }" in html
    # presence read from collectors, treating only unconfigured as absent
    assert 'c.available===false && c.error==="unconfigured"' in html
    # safe default: present unless proven absent
    assert "var _present={gpu:true, litellm:true}" in html


def test_settings_model_cost_override_ui():
    """Model-costs card exposes each model's $/1M cost and lets an admin PIN it (per-model
    cost input + action=cost / cost_reset), so an unreliable LiteLLM price can be corrected
    from the UI. Guards the wiring + the fields it reads."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    # the three per-type rates (input/output/cache) are now EDITABLE inputs, each pinnable
    assert 'input.mrate' in html                             # editable per-type rate cells
    assert "function mcellEdit(" in html
    assert "mcellEdit(m.in_1m" in html and "mcellEdit(m.out_1m" in html \
        and "mcellEdit(m.cache_1m" in html
    # Save posts a per-type cost override (in/out/cache); Reset clears it
    assert 'action:"cost"' in html and "in_1m:vi" in html and "out_1m:vo" in html \
        and "cache_1m:vc" in html
    assert 'action:"cost_reset"' in html
    # a card-level Refresh re-pulls all costs from LiteLLM
    assert 'id="models-refresh"' in html and "loadModels(true)" in html
    # IN/OUT/CCH each keep their OWN explanatory tooltip, now also click-openable
    assert "var MCOL_TIP" in html
    assert "PROMPT tokens" in html and "COMPLETION tokens" in html and "PROMPT-CACHE hit" in html
    assert "function showTip(" in html and '"r tiplbl"' in html   # clickable column labels


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
_PAGES = ["index", "gpu", "litellm", "ollama", "llamacpp", "vllm", "alerts"]
_WINDOWED = ["index", "gpu", "litellm", "llamacpp", "ollama", "vllm", "spend"]   # have the window nav + range
_LLM_PAGES = ["litellm", "ollama", "llamacpp", "vllm"]                  # default window = 24h


def _page(name):
    return (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")


def test_backend_nav_logos_present_and_wired():
    """The three LLM-backend nav entries use their official logos: the SVG assets exist,
    every page's sidebar carries the logo classes (no leftover emoji), the two mono llama
    marks tint via CSS mask (theme-aware), and vLLM keeps its 2-colour brand mark."""
    for f in ("ollama", "llamacpp", "vllm"):
        p = ROOT / "web" / "assets" / "logos" / f"{f}.svg"
        assert p.exists(), f"logo asset {f}.svg missing"
        assert "<svg" in p.read_text(encoding="utf-8"), f"{f}.svg is not an SVG"
    for name in ("index", "gpu", "litellm", "ollama", "llamacpp", "vllm", "spend",
                 "alerts", "settings", "admin", "account"):
        html = (ROOT / "web" / f"{name}.html").read_text(encoding="utf-8")
        assert 'class="navlogo nl-ollama"' in html, f"{name}: Ollama nav logo missing"
        assert 'class="navlogo nl-llamacpp"' in html, f"{name}: llama.cpp nav logo missing"
        assert 'class="navlogo nl-vllm"' in html, f"{name}: vLLM nav logo missing"
        assert "🦙 Ollama" not in html and "⚡ vLLM" not in html, f"{name}: stale emoji nav"
        # mono llamas → currentColor via mask (theme+hover safe); vLLM → its own colours
        assert 'mask-image:url("/assets/logos/ollama.svg")' in html
        assert 'nl-vllm::before{background:url("/assets/logos/vllm.svg")' in html


def test_vllm_page_static_invariants():
    """QA for the vLLM dashboard page: title/header, XSS-safe rendering (escapeHtml +
    DOMPurify, a single innerHTML sink), timer cleanup on unload, the shared header
    time-window control (incl. MTD) + range wiring, and the vLLM KPI hooks."""
    html = _page("vllm")
    assert "<title>AI-Monitoring · vLLM</title>" in html and "<h1>vLLM</h1>" in html
    # XSS-safe: escapeHtml helper + DOMPurify.sanitize, exactly one innerHTML sink
    assert "function escapeHtml" in html and "DOMPurify.sanitize" in html
    assert html.count(".innerHTML") == 1, "vllm.html must have a single innerHTML sink"
    # interval timers are tracked and cleared on unload (no leak)
    assert "_timers" in html and 'addEventListener("beforeunload"' in html
    # unified header window control incl. month-to-date + range wiring
    for w in ("15m", "1h", "24h", "30d", "12mo", "month"):
        assert f'data-w="{w}"' in html, f"vllm: missing window {w}"
    assert "function wsecs(" in _core_js() and "WSECS[WIN]" not in html   # month-aware (core)
    assert 'id="range-dates"' in html and "function fmtRange(" in html
    # vLLM-specific KPIs surfaced (queue pressure / KV cache — the headline signals)
    assert "waiting" in html and "kv_cache" in html


def test_sidebar_gpu_between_overview_and_litellm():
    """regression: sidebar order is Overview → GPU → LiteLLM on every page."""
    for name in _PAGES:
        html = _page(name)
        # nav labels carry an icon prefix (e.g. "🏠 Overview"), so anchor on the
        # closing text, not "href=…>Label", which the icon now sits between.
        o = html.find('Overview</a>')
        g = html.find('GPU/CPU</a>')
        ll = html.find('LiteLLM</a>')
        assert o >= 0 and g >= 0 and ll >= 0, f"{name}: nav links missing"
        assert o < g < ll, f"{name}: sidebar order must be Overview < GPU < LiteLLM"


def test_gpu_page_titled_gpu_cpu_and_has_cpu_cores_stack():
    """GPU page is titled 'GPU/CPU' and carries a stacked CPU-cores-usage card at the
    BOTTOM (after the GPU-metrics charts), fed from the per-core buffer via updateSeries."""
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    assert "<title>AI-Monitoring · GPU/CPU</title>" in html
    assert "<h1>GPU/CPU</h1>" in html
    assert 'id="card-cpucores-stack"' in html and 'id="cpucores-chart"' in html
    assert "renderCpuCoresStack" in html and "updateSeries(cpuCoresChart" in html
    assert "stacked:true" in html                              # it's a STACKED chart
    # grouped with the CPU cores: directly below the per-core sparkline grid, above the
    # GPU-metrics-over-time card
    assert (html.index('id="card-percpu"')
            < html.index('id="card-cpucores-stack"')
            < html.index('id="card-charts"'))


def test_metrics_over_time_is_full_width():
    """regression: the charts card spans every grid column (was ~50% at span-2)."""
    for name in ("gpu", "litellm"):
        html = _page(name)
        assert ".span-full{grid-column:1/-1}" in html, f"{name}: .span-full CSS missing"
        assert 'class="card span-full" id="card-charts"' in html, \
            f"{name}: charts card must use span-full, not span-2"


def test_llm_pages_default_to_24h_window():
    """regression: LiteLLM/Ollama/llama.cpp open on a 24h window by default (the fallback
    when nothing is saved), and the static markup's active button is 24h. The live window is
    now restored per-page from localStorage (see test_window_selection_persists_per_page)."""
    for name in _LLM_PAGES:
        html = _page(name)
        assert '_winRestore("#windows", "24h"' in html, f"{name}: default WIN fallback must be 24h"
        assert 'data-w="24h" class="active"' in html, \
            f"{name}: the 24h button must be the static-default active one"
        assert '<button data-w="1h" class="active">' not in html, \
            f"{name}: the 1h button must no longer be active"


def test_window_selection_persists_per_page():
    """The time-window selection must stick PER PAGE across refresh: restored from a
    path-keyed localStorage entry on load, saved on change. Guards the wiring on every
    windowed page (WIN pages via #windows, spend via #sp-windows)."""
    # The persistence machinery (_winKey/_winSave/_winRestore) lives in the shared core module
    # (review D-3); each WIN page just CALLS it. Guard both halves.
    core = _core_js()
    assert 'localStorage.setItem(_winKey()' in core and 'function _winKey(' in core, \
        "core: window persistence machinery missing"
    assert '"aimon-win:"+location.pathname' in core, "core: window key must be per-page (path)"
    for name in ("index", "gpu", "ollama", "llamacpp", "litellm", "vllm", "network"):
        html = _page(name)
        assert '_winRestore("#windows"' in html, f"{name}: window not restored on load"
        assert "WIN=b.dataset.w; TIMEEND=null; _winSave(WIN, null)" in html, \
            f"{name}: window change must reset the pan cursor and be saved as a live named window"
    # spend keeps its OWN coarser persistence (_spWin*, bare window name, no pan cursor)
    sp = _page("spend")
    assert '_spWinRestore("#sp-windows"' in sp and "SPWIN=b.dataset.w; _spWinSave(SPWIN)" in sp, \
        "spend page window must persist per page too"


_WIN_PAGES = ["index", "gpu", "ollama", "llamacpp", "litellm", "vllm", "network"]


def test_drag_to_zoom_wired_on_every_win_page():
    """Kibana-style drag-to-zoom: dragging across any chart sets a custom time window.
    The delegated pointer-drag handler lives in the shared core module (review D-3); each WIN
    page loads it and supplies the overlay CSS + chart-wraps it operates on."""
    core = _core_js()
    assert "drag-to-zoom: drag across ANY chart" in core, "core: drag handler missing"
    assert "addEventListener(\"pointerdown\"" in core, "core: no pointerdown listener"
    assert "addEventListener(\"pointerup\"" in core, "core: no pointerup listener"
    assert 'WIN="custom:"+Math.round(t2-t1); TIMEEND=t2; _winSave(WIN, TIMEEND)' in core, \
        "core: drag must set a custom window + absolute end and persist it"
    assert 'ov.className="drag-sel"' in core, "core: selection overlay not created"
    for name in _WIN_PAGES:
        html = _page(name)
        assert "/assets/aimon-core.js" in html, f"{name}: does not load the shared drag handler"
        assert ".drag-sel{" in html and ".chart-wrap{position:relative}" in html, \
            f"{name}: drag overlay CSS missing"


def test_every_chart_is_reachable_by_the_drag_handler():
    """The drag handler finds its chart via closest('.chart-wrap'), so a chart that is NOT
    inside one is silently NOT drag-zoomable. Asserting only that the handler exists in the
    file would pass on a page with zero chart-wraps — this checks the containers instead:
    every static <canvas> sits in a .chart-wrap (the host sparkline is deliberately exempt),
    and pages that build charts at runtime create the wrapper around the canvas."""
    for name in _WIN_PAGES:
        html = _page(name)
        statics = re.findall(r'<div class="chart-wrap"[^>]*>\s*<canvas', html)
        dynamic = ('wrap.className="chart-wrap"' in html
                   and "wrap.appendChild(cv)" in html)
        assert statics or dynamic, f"{name}: no chart lives inside a .chart-wrap"
        # every static canvas is either wrapped or an explicitly-exempt sparkline
        for m in re.finditer(r'<div class="([a-z-]+)"[^>]*>\s*<canvas id="([\w-]+)"', html):
            cls, cid = m.group(1), m.group(2)
            assert cls == "chart-wrap" or cid.endswith("-spark"), \
                f"{name}: canvas #{cid} sits in .{cls}, so it cannot be drag-zoomed"


def test_drag_only_starts_on_a_time_series_plot_area():
    """Two ways a naive drag handler goes wrong, both guarded here:
    (1) Chart.js paints the LEGEND on the same canvas, so starting a drag anywhere in the
        wrap swallows the click that toggles a series — the drag must begin inside chartArea;
    (2) a by-key BAR chart's x-axis is key names, not time, so mapping pixels to a time range
        there is meaningless — only charts stamped with real timestamps ($ts) are draggable.
    preventDefault must also wait for the 5px threshold, or it fires on every plain click.
    The handler lives in the shared core module (review D-3)."""
    core = _core_js()
    assert "if(x<a.left||x>a.right||y<a.top||y>a.bottom) return;" in core, \
        "core: drag may start outside the plot area (legend clicks get swallowed)"
    assert "if(!ch.$ts || ch.$ts.length<2) return;" in core, \
        "core: non-time-series charts must not be draggable"
    assert "if(Math.abs(e.clientX-dg.x0)<5) return;      // still a click, not a drag" in core, \
        "core: drag threshold must precede preventDefault"
    assert 'addEventListener("pointercancel",abort)' in core and \
           'window.addEventListener("blur",abort)' in core, \
        "core: a lost pointer must not leave a stuck selection overlay"


def test_drag_maps_pixels_to_real_timestamps_not_window_fractions():
    """The server omits empty buckets (GROUP BY only yields buckets holding rows), so plotted
    points are NOT evenly spread across the window after a restart/outage. Mapping a drag by
    pixel fraction alone would then select the wrong times, silently. Every time-series chart
    records its points' real timestamps via stampTs(), and the drag resolves pixel → point
    index → that point's timestamp. The helper + resolver live in the shared core (D-3); the
    per-page duty is to CALL stampTs() on every time series it plots."""
    core = _core_js()
    assert "function stampTs(ch, pts)" in core, "core: stampTs helper missing"
    assert "xs.getValueForPixel(px1)" in core and "ts[i1]" in core, \
        "core: drag must resolve pixels through the chart's own timestamps"
    for name in _WIN_PAGES:
        html = _page(name)
        # every path that feeds a time series into a chart must stamp it
        for m in re.finditer(r'^\s*(\w[\w.$\[\]]*)\.data\.labels\s*=\s*(?!\[\])', html, re.M):
            line = html[m.start():html.index("\n", m.start())]
            if ("spark" in line.lower() or "keysChart" in line or "userKeysChart" in line
                    or "WinSpend" in line):   # the by-key/by-user SPEND bars are not time-series
                continue                       # sparkline + by-key bar charts: not draggable
            assert "stampTs" in line or "stampTs" in html[m.start() - 120:m.start()], \
                f"{name}: chart data set without stampTs → drag would fall back to guessing: {line.strip()}"


def test_custom_window_token_never_reaches_the_ui():
    """Bug-registry class #3/#4 (a raw token rendered as user-visible text): window badges
    must go through wlabel(), which shows 'custom' instead of 'custom:900'. A restored custom
    range must also be visibly marked as not-live."""
    assert "function wlabel(w)" in _core_js(), "core: wlabel helper missing"
    for name in _WIN_PAGES:
        html = _page(name)
        assert not re.search(r'textContent\s*=\s*WIN\b', html), \
            f"{name}: a window badge still renders the raw WIN token"
        # .custom-win{ styling is per-page; _winMark(true) is invoked from the shared core's
        # _winRestore/drag handler when a frozen custom range is restored.
        assert ".custom-win{" in html, f"{name}: missing not-live marker styling"
    assert "_winMark(true)" in _core_js(), "core: restored custom range must be marked not-live"


def test_restored_window_value_is_injection_hardened():
    """SECURITY: the persisted window value comes from localStorage (attacker-writable in a
    same-origin compromise). Two sinks must be guarded:
    (1) `_winCustom` must match STRICT `custom:<digits>` only — a loose check let
        `custom:3600&x=1` through, and WIN flows unencoded into the export URL + api() query
        string (parameter injection);
    (2) the restored value is interpolated into a `querySelector('… [data-w="'+w+'"]')`, so it
        must be charset-guarded first or a malformed value throws and crashes page init.
        Both guards live in the shared core's _winCustom/_winRestore (review D-3)."""
    core = _core_js()
    assert '/^custom:[0-9]+$/.test(w)' in core, \
        "core: _winCustom must strictly match custom:<digits> (anti param-injection)"
    assert "/^[a-z0-9]+$/i.test(w) && document.querySelector(sel+' button[data-w=" in core, \
        "core: restored value must be charset-guarded before the querySelector interpolation"


def test_custom_marker_is_cleared_when_returning_to_a_named_window():
    """Regression: the not-live marker set on a drag-selected range must be CLEARED when the
    user picks a named window or hits Live — otherwise the badge keeps reading e.g. '1h (not
    live)' after leaving the custom range. Both the window-button handler and the Live handler
    must call _winMark(false)."""
    for name in _WIN_PAGES:
        html = _page(name)
        # window buttons: clear the marker and re-label to the (named) window
        assert 'WIN=b.dataset.w; TIMEEND=null; _winSave(WIN, null); _winMark(false);' in html, \
            f"{name}: window-button must clear the custom marker"
        assert 'if(_wl)_wl.textContent=wlabel(WIN)' in html, \
            f"{name}: window-button must reset the label off 'custom'"
        # Live also clears it
        assert 'TIMEEND=null; _winMark(false); _winSave(WIN, null);' in html, \
            f"{name}: Live must clear the custom marker"


def test_export_follows_the_zoom_and_pan_cursor():
    """CSV export took only `window=`, so a zoomed/panned view exported a same-duration
    window ending NOW — not the range on screen."""
    for name in _WIN_PAGES:
        html = _page(name)
        assert '"/api/export?window="+WIN+"&format=csv"' in html, f"{name}: export link changed"
        assert '(TIMEEND?("&end="+Math.round(TIMEEND)):"")' in html, \
            f"{name}: export must forward the pan/zoom cursor"
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "db.series, window, 1000, end=_q_end(request)" in src, \
        "export_handler must honour ?end= (via the off-loop to_thread read)"


def test_custom_window_flows_through_api_and_wsecs_on_every_win_page():
    """A custom range must reach the server: wsecs() resolves 'custom:<secs>' to its
    seconds, and api() appends the absolute end for every windowed endpoint (not a
    hard-coded endpoint list) so the server derives start=end-secs."""
    assert 'w.indexOf("custom:")===0' in _core_js(), "core: wsecs does not parse custom windows"
    for name in _WIN_PAGES:
        html = _page(name)
        assert re.search(r'TIMEEND && path\.indexOf\("window="\)>=0', _core_js()) \
            and 'end="+TIMEEND' in _core_js(), \
            "the shared api() (aimon-core.js) must append end for any windowed endpoint"
        assert "/assets/aimon-core.js" in html, f"{name}: must load the shared core module"


def test_custom_window_persistence_is_restored_on_refresh():
    """The saved entry is {w,end}; on load a custom range restores both the window token
    AND its absolute end (TIMEEND) so the zoom survives a refresh. Machinery lives in the
    shared core (review D-3); every WIN page loads it."""
    core = _core_js()
    assert 'JSON.stringify({w:w, end:(end||null)})' in core, \
        "core: window state must be persisted as {w,end}"
    assert 'function _winCustom(w)' in core, "core: _winCustom helper missing"
    assert 'TIMEEND=Number(s&&s.end)||null;' in core, \
        "core: custom range must restore its absolute end, coerced to a number"
    for name in _WIN_PAGES:
        assert "/assets/aimon-core.js" in _page(name), f"{name}: does not load core persistence"


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


def test_spend_page_pans_every_chart():
    """Spend pan: ◀▶/● Live drive a single TIMEEND cursor that rangedReload() applies to
    ALL four Spend charts (usage, cost-by-key, cost-per-model, model×user); a window-size
    change resets to live. Data is day-granular, so drag-to-zoom is intentionally OFF here
    (Spend charts are never stampTs'd) — only ◀▶ pan."""
    html = _page("spend")
    for btn in ("nav-left", "nav-right", "nav-live"):
        assert f'id="{btn}"' in html, f"spend: {btn} missing"
    assert "let TIMEEND=null;" in html
    m = re.search(r"function rangedReload\(\)\{([^}]*)\}", html)
    assert m, "spend: rangedReload missing"
    for fn in ("loadSpendSeries()", "loadModelCostSeries()",
               "loadModelUserCostSeries()", "loadKeyCost()"):
        assert fn in m.group(1), f"spend: rangedReload must fan out to {fn}"
    assert "TIMEEND=null; updateRangeUI(); rangedReload();" in html   # size change → live
    assert "stampTs(" not in html, "spend: charts must not be stampTs'd (drag-zoom stays off)"


def test_alerts_status_timeline_pan_wired():
    """Alerts full parity: the status-timeline card gains ◀▶ pan + ● Live + start→end range.
    Alerts carries its OWN api() (no aimon-core), so loadStatus() appends the `end=` cursor
    itself; window buttons are scoped to [data-w] so the nav arrows don't clobber the size."""
    html = _page("alerts")
    for btn in ("nav-left", "nav-right", "nav-live"):
        assert f'id="{btn}"' in html, f"alerts: {btn} missing"
    assert 'id="range-dates"' in html and "let TIMEEND = null;" in html
    assert "function updateRangeUI(" in html and "_dt.textContent" in html
    assert '"&end=" + TIMEEND.toFixed(0)' in html, "alerts: loadStatus must append the pan cursor"
    assert '#status-wins button[data-w]' in html                     # nav arrows excluded
    assert "statusWin = b.dataset.w; TIMEEND = null;" in html        # size change → live


def test_usertokens_stacked_svg_supports_drag_select():
    """The '/litellm Usage by user over time' stacked view is a hand-rolled <svg> (not a
    Chart.js canvas), so the shared aimon-core drag-zoom can't hook it. It carries its OWN
    drag-to-select-a-range that sets a custom window + pan cursor and reloads — so a range can
    be defined ON this graph like the canvas over-time charts."""
    html = _page("litellm")
    assert 'id="ut-stack"' in html
    for h in ("svg.onpointerdown", "svg.onpointermove", "svg.onpointerup"):
        assert h in html, f"ut-stack missing {h}"
    assert "const utPxT=" in html, "drag must map pixels → epoch via bucket timestamps"
    # drag outcome mirrors aimon-core: custom window + TIMEEND cursor + mark + reload
    assert 'WIN="custom:"' in html and "TIMEEND=t2" in html
    assert "_winMark(true)" in html and "rangedReload();" in html


def test_spend_cost_handlers_honour_end_cursor():
    """Every Spend series endpoint reads the ?end= pan cursor and anchors its window there
    (not hard-pinned to now); the two cached handlers never serve/store a panned response."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    for fn in ("spend_series_handler", "spend_model_series_handler",
               "spend_model_user_series_handler"):
        i = src.index(f"async def {fn}")
        body = src[i:src.index("\nasync def ", i + 1)]
        assert "_q_end(request)" in body, f"{fn}: must read the ?end= cursor"
        assert "anchor" in body, f"{fn}: must anchor the window on the cursor"
    for fn in ("spend_series_handler", "spend_model_user_series_handler"):
        i = src.index(f"async def {fn}")
        assert "end_q is None" in src[i:src.index("\nasync def ", i + 1)], \
            f"{fn}: panned view must bypass the cache"


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


def test_gpu_stacked_per_core_cpu_chart_fills_to_previous_dataset():
    """Same fill-to-origin defect as the per-app CPU stack (bug-registry class #1), found in
    a SECOND stacked chart on the same page: the per-core CPU stack shares the identical
    y:{stacked:true} + fill:true pattern, so its translucent bands blend into each other too.
    Scoped to renderCpuCoresStack specifically so a regression here can't hide behind the
    per-app chart's (already-correct) occurrence of the same substring."""
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    m = re.search(r"function renderCpuCoresStack\(\)\{.*?\n\}", html, re.S)
    assert m, "renderCpuCoresStack not found"
    assert re.search(r'fill:\s*i\s*\?\s*["\']-1["\']\s*:\s*["\']origin["\']', m.group(0)), \
        "per-core CPU stack must fill to previous dataset, not to zero"
    assert "fill:true" not in m.group(0), \
        "per-core CPU stack regressed to filling every band to the zero axis"


def test_llamacpp_page_shows_cpu_threads_against_core_count():
    """A thread count means nothing on its own — "10 threads" only answers "why are cores
    idle?" when read against the cores available. The KPI must render both, and degrade to
    "—" when the build's /props omits them rather than implying zero threads."""
    html = (ROOT / "web" / "llamacpp.html").read_text(encoding="utf-8")
    assert "CPU threads" in html
    assert "n_threads" in html and "n_threads_batch" in html
    # the core count is sourced from the same snapshot and shown alongside
    assert "HOST_NCPU" in html
    assert re.search(r'HOST_NCPU\s*=\s*\(c\.host&&c\.host\.ncpu\)', html), \
        "core count must come from the host collector on the same snapshot"
    # absent values render as an em dash, never as 0
    assert re.search(r'lc\.n_threads!=null\?lc\.n_threads:"—"', html)
    assert re.search(r'lc\.n_threads_batch!=null\?lc\.n_threads_batch:"—"', html)


def test_team_rollup_refuses_to_score_mixed_cap_periods():
    """The by-team rollup summed every key's spend and divided by the summed budgets with
    no regard for period. A team mixing a key whose spend RESETS with one whose spend is
    ALL-TIME therefore added two different periods and scored the result — enough to paint
    a team 'Critical' off meaningless arithmetic. It must withhold the % and say why."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    # grouping records each contributing key's basis
    assert re.search(r'bases\[r\.cap_basis\]', html), "team rollup must track cap_basis"
    # and refuses a single % when they disagree
    assert re.search(r'mixed\s*=\s*bs\.length\s*>\s*1', html)
    assert re.search(r'!mixed', html), "team % must be withheld when periods are mixed"
    # the card explains the withheld % rather than looking like a missing budget
    assert "mixed periods" in html
    assert "cannot be added and scored" in html


def test_per_key_lifetime_cap_still_shows_real_percent_and_status():
    """REGRESSION: an interim version replaced a lifetime-cap key's % and status pill with
    the literal text "All-time", which HID a key that was over its cap — it rendered
    "All-time" instead of "Critical". A lifetime cap is a real cap (spend and cap are both
    all-time), so the number and status must always render; only the basis is annotated."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    assert "cap_basis" in html
    # the status pill must render the real label, never be swapped for a basis word
    assert re.search(r'>\$\{SLBL\[r\.status\]\}<', html), \
        "status pill must always show the real status label"
    assert '"All-time":SLBL[r.status]' not in html, "status must not be masked by basis"
    # the percentage itself is still rendered (not replaced by a basis word)
    assert re.search(r'\$\{ipct\}%', html), "per-key % must always render"
    # and the two different percentages are explained rather than left to look contradictory
    assert "answer different questions" in html


def test_spend_model_chart_discloses_cost_provenance():
    """The cost summary uses LiteLLM's actual cash while the per-model chart may be a
    tokens × price estimate — and a model with no price cannot be charted at all. The card
    must state its basis AND name the models missing from it, otherwise the breakdown
    looks complete while being short of the headline."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    assert 'id="model-cost-note"' in html
    assert "cost_basis" in html and "unpriced" in html
    # the warning must say the missing spend IS counted in the summary above
    assert re.search(r'could not be priced', html)
    assert re.search(r'NOT in this chart', html)


def test_sampling_loop_persists_per_core_cpu():
    """The per-core charts are only windowed because the sampling loop WRITES per-core
    samples every tick. If that call is dropped, the DB/API/UI all still pass their own
    tests while the charts quietly go empty — so pin the wiring here."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "db.insert_cpu_core_series(" in src, \
        "sampling loop must persist host.cpu_per_core"
    assert re.search(r'db\.insert_cpu_core_series\(\s*snap\[.ts.\]\s*,[^)]*cpu_per_core',
                     src), "per-core must be written with the snapshot's own timestamp"
    # and the tiered prune must cover the per-core tables (retention, not unbounded growth)
    dbsrc = (ROOT / "db.py").read_text(encoding="utf-8")
    for tbl in ("cpu_core_series", "cpu_core_series_1m", "cpu_core_series_1h"):
        assert re.search(rf'DELETE FROM {tbl} WHERE', dbsrc), f"{tbl} is never pruned"


def test_gpu_per_core_charts_honour_the_window():
    """REGRESSION: the per-core grid + stacked-cores chart used to buffer live samples in
    the browser, so they ignored the page's window/pan controls entirely — selecting
    12:14–13:14 still rendered 'the last few minutes of now'. Both must now be driven by
    the windowed /api/cpuseries endpoint and redraw when the window or pan changes."""
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    assert "/api/cpuseries" in html and "loadPerCpu" in html
    # the client-side rolling buffer is gone
    assert "_percpuBuf" not in html, "per-core still uses the live client buffer"
    assert "PERCPU_MAX_PTS" not in html
    # both views read the windowed points, not wall-clock 'now'
    assert "_percpuPts" in html
    assert "Date.now()/1000,cores:" not in html, "still timestamping with wall-clock now"
    # window switch AND pan both refresh the per-core data
    assert re.search(r'loadSeries\(\);\s*loadAppCpu\(\);\s*loadPerCpu\(\);', html), \
        "window/pan handlers must reload the per-core series"
    # pan offset (`end=`) is forwarded for cpuseries like every windowed endpoint
    assert '/api/cpuseries?window=' in html, "per-core must request the windowed cpuseries endpoint"
    assert re.search(r'TIMEEND && path\.indexOf\("window="\)>=0', _core_js()) \
        and 'end="+TIMEEND' in _core_js(), \
        "the shared api() (aimon-core.js) attaches the pan `end=` param for every windowed endpoint"


def test_gpu_per_core_cpu_grid():
    """The GPU page shows a per-core CPU usage grid: one sparkline per logical CPU, built
    dynamically from the windowed /api/cpuseries payload (see
    test_gpu_per_core_charts_honour_the_window for the window/pan contract)."""
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    assert 'id="card-percpu"' in html and 'id="percpu-grid"' in html
    assert "renderPerCpuGrid" in html and "buildPerCpu" in html
    # driven by the persisted, windowed series
    assert "/api/cpuseries" in html
    assert "mkPerCpuChart" in html
    # updates values in place (poll-safe); the global rebuild ban is enforced elsewhere
    assert re.search(r'datasets\[0\]\.data=', html), "per-core charts must update in place"
    # placed above the GPU-metrics time-series card
    assert html.index('id="card-percpu"') < html.index('id="card-charts"')


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


def test_regression_all_test_files_are_allow_listed():
    """Every tests/test_*.py must ship in the publish ALLOW-list — otherwise the PUBLIC repo's
    CI + the Dockerfile in-image gate run a SMALLER suite than the dev box (a new/renamed test
    file is silently dropped from the shipped product's quality gate). Was the case for 7 files
    (~69 tests). `_internal_markers.py` is deliberately private (guarded try/except everywhere)."""
    allow = _publish_allow_list()
    if allow is None:
        return
    on_disk = sorted(p.name for p in (ROOT / "tests").glob("test_*.py"))
    for name in on_disk:
        assert ("tests/" + name) in allow, \
            f"tests/{name} exists but is NOT in the publish ALLOW-list — it won't ship / won't gate"


def test_regression_all_helm_templates_are_allow_listed():
    """Every Helm chart template must ship in the publish ALLOW-list — a template left out is
    silently dropped from `helm install` in the PUBLIC repo. This bit networkpolicy.yaml (a
    security control: without it the pod has no NetworkPolicy at all), so a new template can't
    be added to the chart without also shipping it."""
    allow = _publish_allow_list()
    if allow is None:
        return
    tdir = ROOT / "deploy" / "helm" / "ai-monitoring" / "templates"
    for p in sorted(tdir.glob("*")):
        if p.is_file():
            rel = str(p.relative_to(ROOT))
            assert rel in allow, f"{rel} exists but is NOT in the publish ALLOW-list — helm install would drop it"


def test_regression_readme_images_are_all_allow_listed():
    """Every docs/img/*.png|svg README references must ship in the publish
    ALLOW-list — a screenshot added to the README but never added to ALLOW silently
    404s for every public reader (the exact gap that slipped through when the
    light-theme gallery's images were first added)."""
    allow = _publish_allow_list()
    if allow is None:
        return
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for m in re.finditer(r'docs/img/[\w.-]+\.(?:png|svg)', readme):
        assert m.group(0) in allow, f"README references {m.group(0)!r}, missing from publish ALLOW-list"


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


def test_keytime_card_states_its_window_semantics():
    """"Top 10 API keys over time" plots CUMULATIVE spend per key, ALL-TIME — a running total
    that only rises (never the old rolling-window count that fell when a key went quiet, which
    read as broken data). The card's sub-note must state the all-time running-total semantics
    and point at the sibling 'requests in window' card for the per-window view."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert 'id="keytime-sub"' in html
    assert "running total" in html and "all time" in html
    # the old rolling-window framing must be gone from the keytime sub-note
    m = re.search(r'ksub\.textContent\s*=.*?;', html, re.S)
    assert m and "rolling window" not in m.group(0), "keytime sub-note must not describe a rolling window"
    assert "only\n" in m.group(0) or "only rises" in m.group(0).replace('"\n    +"', ""), \
        "keytime sub-note must state the line only rises"


def test_test_db_path_is_per_process():
    """The suite's SQLite path must be unique per process. It was fixed, so two pytest
    runs on one machine shared a file while the autouse fixture DELETEs users/tokens
    before every test — each run wiped the other's fixtures mid-test and produced
    unrelated 401 / KeyError('csrf') failures that looked like real auth bugs."""
    src = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert "MONITOR_DB_PATH" in src
    assert "getpid()" in src, "test DB path must be per-process to survive concurrent runs"


def test_auth_reset_fixture_clears_every_lockout_map():
    """The autouse reset must clear BOTH lockout tiers plus token sessions. The per-account
    maps were added after the fixture was written and went unreset, so a test that failed
    logins for a user left that account locked for every later test — making the suite pass
    or fail on collection order alone."""
    src = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    for name in ("_auth_fails", "_auth_locked_until",      # per-IP
                 "_user_fails", "_user_locked_until",      # per-account
                 "_token_sessions"):
        assert re.search(rf'{name}\.clear\(\)', src), f"{name} is never reset between tests"


def test_publish_allowlist_covers_every_collector_and_page():
    """§9a publish parity: a new backend's collector + dashboard must be added to the
    publish ALLOW-list or it silently never reaches the public repo — the app would ship
    with a nav link to a page that isn't there. vLLM was added and initially missed."""
    allow = _publish_allow_list()
    if allow is None:
        pytest.skip("publisher not checked out")
    allow = set(allow)
    import glob as _glob
    for f in _glob.glob(str(ROOT / "collectors" / "*.py")):
        name = "collectors/" + os.path.basename(f)
        if os.path.basename(f) == "__init__.py" or name in allow:
            continue
        assert False, f"{name} is not in the publish ALLOW-list"
    for f in _glob.glob(str(ROOT / "web" / "*.html")):
        name = "web/" + os.path.basename(f)
        assert name in allow, f"{name} is not in the publish ALLOW-list"


def test_vllm_page_has_no_llamacpp_identity_left():
    """REGRESSION: the page was seeded from the llama.cpp template and its chart card was
    still titled "llama.cpp over time" in production. Any llama.cpp product name outside
    the shared sidebar/CSS is a leftover."""
    html = (ROOT / "web" / "vllm.html").read_text(encoding="utf-8")
    assert "vLLM over time" in html
    body = "\n".join(ln for ln in html.splitlines()
                     if 'href="/llamacpp"' not in ln and "nl-llamacpp" not in ln
                     and "logos/llamacpp" not in ln and "were llama.cpp" not in ln)
    assert "llama.cpp over time" not in body
    # throughput + memory-pressure fields are surfaced
    assert "Prompt tokens/s" in html and "Generated tokens/s" in html
    assert "Swapped" in html
    # cumulative totals are labelled as such, not passed off as current values
    assert "cumulative since vLLM started" in html
    # summed multi-model figures are disclosed
    assert "SUMMED across them" in html


def test_vllm_page_explains_idle_vs_unreachable_metrics():
    """"No traffic yet" and "cannot read /metrics" both produce empty fields but need
    opposite responses from an operator, so the page must not render them identically."""
    html = (ROOT / "web" / "vllm.html").read_text(encoding="utf-8")
    assert "awaiting_traffic" in html
    assert "no requests since it (re)started" in html
    assert "only created on the first request" in html


def test_vllm_page_translates_raw_collector_errors():
    """Collector errors are raw Python exception names ("conn: ClientConnectorError",
    "TimeoutError"). Shown verbatim they read as the dashboard being broken and tell an
    operator nothing about what to fix, so the page maps the known ones to an action —
    while still showing an UNKNOWN error rather than swallowing it."""
    html = (ROOT / "web" / "vllm.html").read_text(encoding="utf-8")
    assert "function friendlyErr" in html
    # the raw string is used as the fallback, so nothing is hidden
    assert re.search(r'return raw;', html), "unknown errors must still be shown"
    # and preserved on hover for diagnosis
    assert re.search(r'title="\$\{escapeHtml\(String\(\(v&&v\.error\)', html)
    # the cases that actually occur
    for pattern in ("ClientConnectorError", "Timeout", "http 401", "http 404"):
        assert pattern in html, f"no mapping for {pattern}"
    # each maps to something actionable, not a class name
    assert "VLLM_BASE_URL" in html and "VLLM_API_KEY" in html


def test_vllm_empty_charts_auto_hide():
    """§12: a chart with no data must hide its tile rather than render an empty axis —
    an empty plot reads as a broken chart. Inherited convention; assert it survived the
    page being seeded from another template."""
    html = (ROOT / "web" / "vllm.html").read_text(encoding="utf-8")
    assert re.search(r'pts\.some\(p=>p\[cfg\.key\]!=null\)\?"":"none"', html), \
        "empty vLLM chart tiles must auto-hide"


def test_alerts_down_breach_shows_recheck_state():
    """A `down:<backend>` breach is re-evaluated on every poll and clears itself once the
    service returns — but with no sign of that it reads as a frozen error, and people
    restart things that were already recovering. The row must show it is being re-checked,
    driven by the page's OWN poll rather than a second timer that could disagree with it."""
    html = (ROOT / "web" / "alerts.html").read_text(encoding="utf-8")
    assert "ALERT_POLL_MS" in html
    assert "paintRecheck" in html
    # the countdown is derived from the real poll, not an independent interval
    assert re.search(r'setInterval\(tick,\s*ALERT_POLL_MS\)', html), \
        "the poll and the countdown must share one interval constant"
    assert re.search(r're-checking in', html)
    assert re.search(r'last checked', html)
    # only backend-down breaches get it: a threshold breach clears when the VALUE moves,
    # so a retry countdown there would promise something that does not happen
    assert re.search(r'\/\^down:\/\.test', html), \
        "recheck indicator must be limited to down: breaches"
    # the 1s ticker repaints text only — it must not issue requests
    assert re.search(r'setInterval\(paintRecheck,\s*1000\)', html)
    # timers still registered for cleanup (§12)
    assert html.count("_timers.push") >= 2


def test_alerts_recheck_only_on_down_breach_behavior():
    """Behavioral: run the REAL active-breach row builder from alerts.html. A
    `down:<backend>` key must emit the `.recheck` countdown element; a threshold
    breach (which clears on a value change, not a retry) must NOT — otherwise the
    UI promises a re-check that never happens. Skipped if node is absent."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    html = (ROOT / "web" / "alerts.html").read_text(encoding="utf-8")
    m = re.search(r'active\.map\(k=>\{([\s\S]*?)\}\)\.join\(""\)', html)
    assert m, "active-breach row builder not found in alerts.html"
    script = "function row(k){" + m.group(1) + "}\n" + """
const escapeHtml = s => String(s);
console.log(JSON.stringify({
  down: row("down:vllm"),
  thr:  row("cpu_pct 95%"),
}));
"""
    out = subprocess.run([node, "-e", script], capture_output=True,
                         text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    assert 'class="recheck"' in r["down"] and "re-checking" in r["down"], \
        f"down: breach missing re-check indicator: {r['down']!r}"
    assert "recheck" not in r["thr"], \
        f"threshold breach must NOT get a re-check countdown: {r['thr']!r}"
    # both must still escape the key (XSS — §12)
    assert "down:vllm" in r["down"]


def test_alerts_recheck_countdown_behavior():
    """Behavioral: run the REAL paintRecheck. The countdown must derive from the
    poll interval and the last-check timestamp, clamp at 0 (never negative), and
    issue NO network request — it only repaints text. Skipped if node is absent."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    html = (ROOT / "web" / "alerts.html").read_text(encoding="utf-8")
    m = re.search(r"function paintRecheck\(\)\{[\s\S]*?\n\}", html)
    assert m, "paintRecheck not found in alerts.html"
    script = m.group(0) + """
const ALERT_POLL_MS = 5000;
let apiCalls = 0;
function api(){ apiCalls++; return Promise.resolve(null); }   // must stay 0
const els = [{textContent:""}, {textContent:""}];
globalThis.document = { querySelectorAll: () => els };
let _lastAlertCheck;
function run(elapsed){ _lastAlertCheck = Date.now() - elapsed; paintRecheck(); return els[0].textContent; }
const r0 = run(0);       // just checked  -> ~5s left
const r3 = run(2000);    // 2s ago        -> ~3s left
const rNeg = run(6000);  // 6s ago (past) -> clamp to 0, not -1
// no .recheck elements at all -> must be a safe no-op, not a throw
globalThis.document = { querySelectorAll: () => [] };
let noElsThrew = false;
try { run(0); } catch(e){ noElsThrew = true; }
console.log(JSON.stringify({r0, r3, rNeg, apiCalls, noElsThrew}));
"""
    out = subprocess.run([node, "-e", script], capture_output=True,
                         text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    assert re.search(r"re-checking in 5s\b", r["r0"]), r["r0"]
    assert "last checked" in r["r0"]
    assert re.search(r"re-checking in 3s\b", r["r3"]), r["r3"]
    assert re.search(r"re-checking in 0s\b", r["rNeg"]), \
        f"countdown must clamp at 0, never go negative: {r['rNeg']!r}"
    assert r["apiCalls"] == 0, "paintRecheck must not issue any network request"
    assert r["noElsThrew"] is False, "paintRecheck must no-op when no .recheck elements exist"


def test_vllm_help_popover_click_toggle_behavior():
    """Behavioral: run the REAL click-help wiring from vllm.html. Help must OPEN on
    click (not hover), close on a second click, allow only one popover open at a
    time, expose an accessible aria-expanded state, stopPropagation so the
    document outside-click handler doesn't instantly re-close it, and closeAllInfo
    must clear everything. Skipped if node is absent."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    html = (ROOT / "web" / "vllm.html").read_text(encoding="utf-8")
    close_fn = re.search(r"function closeAllInfo\(\)\{[\s\S]*?\n\}", html)
    block = re.search(r'const info=document\.createElement\("button"\);'
                      r'[\s\S]*?nm\.append\(" ",info,pop\);', html)
    assert close_fn and block, "could not extract the click-help wiring"
    harness = """
const ALL = [];
function el(tag){
  const classes = new Set(); const attrs = {}; const listeners = {};
  const node = { tagName: tag, type: "", textContent: "",
    classList: { add:c=>classes.add(c), remove:c=>classes.delete(c), contains:c=>classes.has(c) },
    _classes: classes, _attrs: attrs, _listeners: listeners,
    setAttribute:(k,v)=>{ attrs[k]=String(v); }, getAttribute:k=>(k in attrs?attrs[k]:null),
    addEventListener:(ev,fn)=>{ (listeners[ev]=listeners[ev]||[]).push(fn); },
    append:(...xs)=>{}, };
  Object.defineProperty(node,"className",{ get:()=>[...classes].join(" "),
    set:v=>{ classes.clear(); String(v).split(/\\s+/).filter(Boolean).forEach(c=>classes.add(c)); } });
  ALL.push(node); return node;
}
function matches(n,sel){
  const am = sel.match(/\\[([\\w-]+)="([^"]*)"\\]/);
  const cls = sel.replace(/\\[[^\\]]*\\]/,"").split(".").filter(Boolean);
  for(const c of cls) if(!n._classes.has(c)) return false;
  if(am) return n._attrs[am[1]] === am[2];
  return true;
}
const document = { createElement: el, querySelectorAll: sel => ALL.filter(n=>matches(n,sel)),
  addEventListener:()=>{} };
"""
    make = ('function makeInfo(cfg, nm){\n' + block.group(0) +
            '\n  return {info, pop};\n}\n')
    driver = """
function clickWith(node){ let stopped=0;
  (node._listeners.click||[]).forEach(f=>f({stopPropagation:()=>{stopped++;}})); return stopped; }
const A = makeInfo({label:"Queue", id:"c-q", desc:"queue depth explanation"}, el("span"));
const B = makeInfo({label:"KV",    id:"c-k", desc:"kv cache explanation"},    el("span"));
const start = !A.pop._classes.has("open") && !B.pop._classes.has("open");
const stoppedA = clickWith(A.info);                                   // open A
const openedA  = A.pop._classes.has("open") && A.info.getAttribute("aria-expanded")==="true";
clickWith(B.info);                                                    // open B, must close A
const oneAtATime = !A.pop._classes.has("open") && B.pop._classes.has("open");
clickWith(B.info);                                                    // toggle B off
const toggledOff = !B.pop._classes.has("open") && B.info.getAttribute("aria-expanded")==="false";
clickWith(A.info); closeAllInfo();                                    // global dismiss
const allClosed = document.querySelectorAll(".info-pop.open").length === 0;
console.log(JSON.stringify({ start, openedA, oneAtATime, toggledOff, allClosed,
  stoppedA, desc: A.pop.textContent, tag: A.info.tagName }));
"""
    script = harness + close_fn.group(0) + "\n" + make + driver
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    assert r["start"], "popovers must start closed"
    assert r["openedA"], "click must open the popover and set aria-expanded=true"
    assert r["oneAtATime"], "opening one popover must close any other (one at a time)"
    assert r["toggledOff"], "a second click must close it and reset aria-expanded"
    assert r["allClosed"], "closeAllInfo must clear every open popover"
    assert r["stoppedA"] >= 1, "click handler must stopPropagation (else outside-click re-closes it)"
    assert r["desc"] == "queue depth explanation", "popover must carry the graph's desc"
    assert r["tag"] == "button", "the help trigger must be a real <button> (keyboard/focus)"


def test_gpu_vram_missing_shows_explained_placeholder():
    """When a GPU reports no VRAM (unified memory, or a metrics feed whose rows omit the
    memory columns — observed live: mode=file, vram_total null), the page must not just
    drop the two VRAM tiles, leaving a silent gap that reads as a bug. It must render a
    '—' VRAM KPI and a note that says WHY, distinguishing the feed-gap case from the
    unified-memory case."""
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    assert 'id="g-vram-note"' in html, "GPU page needs a VRAM-explanation note element"
    assert 'kpi("VRAM", "—")' in html, "a '—' VRAM tile must replace the dropped pair"
    # both causes are worded, and the feed-gap wording is gated on the file/url source
    assert "not reported by this GPU feed" in html
    assert "unified memory" in html
    assert re.search(r'g\.mode==="file"\|\|g\.mode==="url"', html), \
        "feed-gap wording must be chosen by the metrics source, not shown unconditionally"


def test_spend_series_default_windows_are_aligned():
    """A param-less call to the two stacked Spend charts must land on the SAME span —
    model-series and model-user-series both default to 30d (the Spend page's own default
    and only-offered daily window). 14d stays a valid explicit granularity but is no
    longer a divergent default."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")

    def _default(handler):
        m = re.search(r"async def " + handler + r"\b[\s\S]*?"
                      r'window = request\.query\.get\("window", "([^"]+)"\)', src)
        assert m, f"could not find window default for {handler}"
        return m.group(1)

    a = _default("spend_model_series_handler")
    b = _default("spend_model_user_series_handler")
    assert a == b == "30d", f"spend chart defaults diverge: model={a} model-user={b}"
    # 14d must remain accepted where the daily rollup supports it (not silently removed)
    assert '"14d", "30d", "12mo", "month"' in src, "14d must stay a valid explicit window"


def test_llamacpp_chart_keys_are_persisted_columns():
    """Every chart on the llama.cpp page reads points[key] from /api/series, and that key
    is only populated if it is a real metric column (db._METRIC_COLS) fed by _metrics_row.
    A chart whose key isn't a column would plot nothing forever. Guards the 3 added charts
    (prompt tok/s, slots busy %, context %) and the originals."""
    import app as appmod
    import db as dbmod
    html = (ROOT / "web" / "llamacpp.html").read_text(encoding="utf-8")
    keys = set(re.findall(r'key:"([a-z0-9]+)"', html))
    assert {"pptok", "busy", "ctxused"} <= keys, f"new llama.cpp charts missing: {keys}"
    cols = set(dbmod._METRIC_COLS)
    missing = keys - cols
    assert not missing, f"chart keys with no metric column (plot nothing): {missing}"
    # and _metrics_row must actually emit the new keys, or the columns stay null
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 1, "mem_pct": 1,
                 "disk": {"pct": 1}, "load": [0, 0, 0]},
        "gpu": {"available": False}, "ollama": {"available": False},
        "litellm": {"available": False},
        "llamacpp": {"available": True, "prompt_per_second": 700.0,
                     "slots_busy_pct": 50.0, "ctx_used_pct": 25.0}}}
    row = appmod._metrics_row(snap)
    assert row["pptok"] == 700.0 and row["busy"] == 50.0 and row["ctxused"] == 25.0
    # unavailable backend -> None, never a stale/fabricated value
    snap["collectors"]["llamacpp"] = {"available": False}
    row2 = appmod._metrics_row(snap)
    assert row2["pptok"] is None and row2["busy"] is None and row2["ctxused"] is None


def test_litellm_page_init_executes_without_js_error():
    """Regression for the '_keytimeMetric before initialization' TDZ crash: the
    keyTimeChart's axis callback reads a `let` that was declared AFTER the chart, so
    Chart.js invoking the callback during construction threw an uncaught ReferenceError
    that halted the whole script — empty charts AND a dead time-window selector. The
    static `new Function()` syntax check can't catch it (it compiles, never runs), so
    execute the page's inline JS with a Chart stub that INVOKES the scale/tooltip
    callbacks at construction (like Chart.js does). Skipped if node is absent."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    scripts = [m.group(1) for m in re.finditer(r"<script>([\s\S]*?)</script>", html)]
    combined = _core_js() + "\n" + "\n".join(scripts)
    harness = r"""
    process.on('unhandledRejection', () => {});
    global.window = global;
    global.CUR = "$";                       // server injects window.CUR before </head>
    global.addEventListener = () => {}; global.removeEventListener = () => {};
    const el = new Proxy(function(){}, { apply: () => el, get(t,p){
      if (typeof p === "symbol") return t[p];
      if (["style","dataset","classList"].includes(p)) return t[p] || (t[p] = {add(){},remove(){},toggle(){},contains(){return false}});
      if (["getContext","querySelector","createElement","closest"].includes(p)) return () => el;
      if (p === "querySelectorAll") return () => [];
      if (p === "getAttribute") return () => null;
      if (typeof t[p] === "function") return t[p];
      if (p in t) return t[p];
      return () => {};
    }, set(t,p,v){ t[p]=v; return true; }});
    global.document = { getElementById: () => el, querySelector: () => el,
      querySelectorAll: () => [], createElement: () => el, addEventListener: () => {},
      body: el, documentElement: el, head: el, cookie: "", title: "" };
    global.location = { search: "?token=x", pathname: "/litellm", href: "", hostname: "x" };
    global.localStorage = { getItem: () => null, setItem: () => {} };
    global.matchMedia = () => ({ matches:false, addEventListener(){} });
    global.setInterval = () => 0; global.clearInterval = () => {}; global.setTimeout = () => 0;
    global.fetch = () => Promise.resolve({ ok:true, status:200, json:()=>Promise.resolve({}), text:()=>Promise.resolve("") });
    global.getComputedStyle = () => ({ getPropertyValue: () => "" });
    // Chart stub that RUNS the callbacks at construction, reproducing the TDZ crash.
    global.Chart = function(_c, cfg){
      try {
        const o = (cfg && cfg.options) || {};
        const sc = o.scales || {};
        for (const k in sc){ const cb = sc[k] && sc[k].ticks && sc[k].ticks.callback; if (cb) cb(0,0,[]); }
        const tt = o.plugins && o.plugins.tooltip && o.plugins.tooltip.callbacks;
        if (tt && tt.label) tt.label({ parsed:{x:0,y:0}, dataset:{label:""}, raw:0 });
      } catch(e){ throw e; }
      const data = (cfg && cfg.data) || { labels:[], datasets:[] };
      (data.datasets || []).forEach(ds => { if (!ds.data) ds.data = []; });
      return { data, update(){}, destroy(){}, options:(cfg && cfg.options) || {} };
    };
    global.Chart.defaults = {};
    global.DOMPurify = { sanitize: s => s };
    """
    script = harness + "\ntry {\n" + combined + \
        '\n} catch (e) { console.error("PAGE_INIT_THREW: " + e.message); process.exit(3); }\n'
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, \
        f"litellm.html init threw a JS error at load:\n{out.stderr.strip()}"
    # and the specific ordering that caused it stays correct
    decl = html.index("let _keytimeMetric")
    use = html.index('new Chart(document.getElementById("keytime-chart")')
    assert decl < use, "_keytimeMetric must be declared BEFORE keyTimeChart (TDZ guard)"


def test_drag_to_zoom_actually_produces_the_selected_range_at_runtime():
    """QA (behavioural, not source-inspection): perform a real drag against the page's own
    handlers and assert the window it produces.

    The static checks prove the code is present; only running it proves the drag resolves to
    the right TIMES. The stub chart plots points at known timestamps and reports a known
    pixel→index mapping, so the assertion is exact: dragging px 10→60 must select the range
    between the points at those indices — proving the handler reads the chart's real
    timestamps rather than interpolating across the requested window. Skipped without node."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    html = _page("litellm")
    combined = _core_js() + "\n" + "\n".join(m.group(1) for m in re.finditer(r"<script>([\s\S]*?)</script>", html))
    harness = r"""
    process.on('unhandledRejection', () => {});
    global.window = global; global.CUR = "$";
    const LISTENERS = {};                         // capture the delegated drag handlers
    const STORE = {};
    const style = () => new Proxy({}, { get:(t,p)=> t[p]||"", set:(t,p,v)=>{t[p]=v; return true;} });
    function mkEl(extra){
      const e = Object.assign({
        style: style(), dataset:{}, className:"", textContent:"", title:"",
        classList:{add(){},remove(){},toggle(){},contains(){return false}},
        appendChild(c){ e._kids=(e._kids||[]).concat([c]); c.parentNode=e; return c; },
        append(){ for (const c of arguments){ if (c && typeof c==="object"){ e._kids=(e._kids||[]).concat([c]); c.parentNode=e; } } },
        prepend(){}, remove(){},
        removeChild(c){ e._kids=(e._kids||[]).filter(k=>k!==c); c.parentNode=null; },
        setAttribute(){}, getAttribute(){ return null; }, addEventListener(){},
        querySelectorAll(){ return []; }, getContext(){ return {}; },
        getBoundingClientRect(){ return {left:0, top:0, right:200, bottom:100}; },
      }, extra||{});
      return e;
    }
    const CANVAS = mkEl({});
    const WRAP = mkEl({ querySelector: () => CANVAS });
    CANVAS.closest = (sel) => sel === ".chart-wrap" ? WRAP : null;
    // a chart whose points sit at KNOWN timestamps, with a known pixel->index mapping
    const TS = [1000,1100,1200,1300,1400,1500,1600,1700,1800,1900,2000];
    const CHART = { chartArea:{left:0,right:100,top:0,bottom:50}, $ts:TS,
                    scales:{ x:{ getValueForPixel:(px)=> px/10 } },
                    data:{labels:[],datasets:[]}, update(){}, destroy(){}, options:{} };
    const el = new Proxy(function(){}, { apply: () => el, get(t,p){
      if (typeof p === "symbol") return t[p];
      if (["style","dataset","classList"].includes(p)) return t[p] || (t[p] = {add(){},remove(){},toggle(){},contains(){return false}});
      if (["getContext","querySelector","createElement","closest"].includes(p)) return () => el;
      if (p === "querySelectorAll") return () => [];
      if (p === "getAttribute") return () => null;
      if (typeof t[p] === "function") return t[p];
      if (p in t) return t[p];
      return () => {};
    }, set(t,p,v){ t[p]=v; return true; }});
    global.addEventListener = (ty,fn) => { (LISTENERS[ty]=LISTENERS[ty]||[]).push(fn); };
    global.removeEventListener = () => {};
    global.document = { getElementById: () => el, querySelector: () => el,
      querySelectorAll: () => [], createElement: () => mkEl({}),
      addEventListener: (ty,fn) => { (LISTENERS[ty]=LISTENERS[ty]||[]).push(fn); },
      body: el, documentElement: el, head: el, cookie: "", title: "" };
    global.location = { search:"?token=x", pathname:"/litellm", href:"", hostname:"x" };
    global.localStorage = { getItem:(k)=> (k in STORE ? STORE[k] : null),
                            setItem:(k,v)=>{ STORE[k]=String(v); } };
    global.matchMedia = () => ({ matches:false, addEventListener(){} });
    global.setInterval = () => 0; global.clearInterval = () => {}; global.setTimeout = () => 0;
    global.fetch = () => Promise.resolve({ ok:true, status:200, json:()=>Promise.resolve({}), text:()=>Promise.resolve("") });
    global.getComputedStyle = () => ({ getPropertyValue: () => "" });
    global.Chart = function(_c, cfg){
      const data = (cfg && cfg.data) || { labels:[], datasets:[] };
      (data.datasets || []).forEach(ds => { if (!ds.data) ds.data = []; });
      return { data, update(){}, destroy(){}, options:(cfg && cfg.options) || {} };
    };
    global.Chart.defaults = {};
    global.Chart.getChart = () => CHART;
    global.DOMPurify = { sanitize: s => s };
    global.__fire = function(type, x){
      (LISTENERS[type]||[]).forEach(fn => fn({ button:0, clientX:x, clientY:10,
        target: CANVAS, preventDefault(){}, }));
    };
    global.__store = STORE;
    """
    # probe() closes over the page's own `let` bindings, so we can read them after the drag
    probe = '\nglobal.__probe = function(){ return {WIN:WIN, TIMEEND:TIMEEND}; };\n'
    drive = r"""
    __fire("pointerdown", 10);          // index 1 -> t=1100
    __fire("pointermove", 60);          // past the 5px threshold -> drag starts
    __fire("pointerup",   60);          // index 6 -> t=1600
    const s = __probe();
    console.log(JSON.stringify({win:s.WIN, end:s.TIMEEND, saved:__store["aimon-win:/litellm"]}));
    """
    script = (harness + "\ntry {\n" + combined + probe +
              '\n} catch (e) { console.error("PAGE_INIT_THREW: " + e.message); process.exit(3); }\n'
              + drive)
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, f"drag run failed:\n{out.stderr.strip()}"
    res = json.loads(out.stdout.strip().splitlines()[-1])
    # points at index 1 (t=1100) and index 6 (t=1600) → a 500s window ending at 1600
    assert res["win"] == "custom:500", \
        f"drag must select the range between the dragged POINTS, got {res['win']}"
    assert res["end"] == 1600, f"window must end at the drag's right-hand point, got {res['end']}"
    assert res["saved"] and '"custom:500"' in res["saved"] and "1600" in res["saved"], \
        f"the custom range must be persisted for this page, got {res['saved']}"


def test_litellm_request_delta_charts_hide_when_no_request_data():
    """The 'Top keys/users — requests in window' charts plot per-key REQUEST counts,
    which lite/off spend mode doesn't have (only per-key spend) — so they came back
    all-zero and rendered as flat-empty. They must auto-hide their card when there's no
    non-zero request data, like the empty mini-charts do, instead of showing flat-zero
    lines. Guards the fix for the two persistently-empty /litellm graphs in lite mode."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    for card, chart in (("card-keydelta", "keyDeltaChart"),
                        ("card-userdelta", "userDeltaChart")):
        assert f'getElementById("{card}")' in html, f"{card} hide-toggle missing"
    # the toggle is driven by whether any datapoint is non-null AND non-zero
    assert re.search(r"labels\.some\(lab=>pts\.some\(p=>p\[lab\]!=null && p\[lab\]!==0\)\)",
                     html), "delta charts must hide on all-zero/null request data"
    assert re.search(r'card-keydelta"\)?;?\s*\n?\s*if\(_kdCard\)\s*_kdCard\.style\.display', html)


_PAGE_JS_HARNESS = r"""
process.on('unhandledRejection', () => {});
global.window = global; global.CUR = "€";
global.addEventListener = () => {}; global.removeEventListener = () => {};
const REG = {};
function mk(id){ return REG[id] || (REG[id] = { id, textContent:"", innerHTML:"", _attrs:{},
  style:{}, dataset:{}, classList:{add(){},remove(){},toggle(){},contains(){return false}},
  setAttribute(k,v){ this._attrs[k]=v; }, getAttribute(k){ return this._attrs[k]||null; },
  getContext(){ return mk(id+":ctx"); }, appendChild(){}, addEventListener(){},
  append(){}, prepend(){}, before(){}, after(){}, replaceChildren(){},
  querySelector(){ return mk(id+":q"); }, querySelectorAll(){ return []; },
  insertAdjacentHTML(){}, remove(){}, focus(){}, closest(){ return mk(id+":c"); } }); }
global.document = { getElementById: id => mk(id), querySelector: () => mk("q"),
  querySelectorAll: () => [], createElement: () => mk("new"), addEventListener: () => {},
  body: mk("body"), documentElement: mk("html"), head: mk("head"), cookie:"", title:"" };
global.location = { search:"?token=x", pathname:"/litellm", href:"", hostname:"x" };
global.localStorage = { getItem: () => null, setItem: () => {} };
global.matchMedia = () => ({ matches:false, addEventListener(){} });
global.setInterval = () => 0; global.clearInterval = () => {}; global.setTimeout = () => 0;
global.fetch = () => Promise.resolve({ ok:true, status:200,
  json:()=>Promise.resolve({}), text:()=>Promise.resolve("") });
global.getComputedStyle = () => ({ getPropertyValue: () => "" });
global.Chart = function(_c, cfg){
  const data = (cfg && cfg.data) || { labels:[], datasets:[] };
  (data.datasets || []).forEach(ds => { if (!ds.data) ds.data = []; });
  // Model Chart.js v4: `chart.options` (resolved) reads through to `chart.config.options`
  // (raw) — same object here. Post-construction option code MUST go via chart.config.options,
  // because mutating the real resolved `chart.options` proxy recurses infinitely (v4.4).
  const opts = (cfg && cfg.options) || {};
  return { data, update(){}, destroy(){}, options: opts, config: { options: opts } };
};
global.Chart.defaults = {}; global.DOMPurify = { sanitize: s => s };
"""


def _probe_page_js(page, probe):
    """Execute a dashboard page's inline JS under a DOM/Chart stub, then run `probe`
    (which must `console.log("PROBE:" + JSON.stringify(obj))`) inside the same scope so
    it can reach the page's `let`-scoped state and functions. Returns the parsed object.

    This exercises RUNTIME behaviour — the static `new Function()` syntax check compiles
    the page but never runs it, so it cannot catch a mislabelled control or a TDZ error.
    Skips when node is unavailable. `REG[id]` is the recorded element for each id.
    """
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioral test")
    html = (ROOT / "web" / page).read_text(encoding="utf-8")
    combined = _core_js() + "\n" + "\n".join(m.group(1) for m in
                         re.finditer(r"<script>([\s\S]*?)</script>", html))
    script = _PAGE_JS_HARNESS + "\ntry {\n" + combined + "\n" + probe + \
        '\n} catch (e) { console.error("THREW: " + e.message); process.exit(3); }\n'
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, f"{page} JS threw:\n{out.stderr.strip()}"
    line = next((ln for ln in out.stdout.splitlines() if ln.startswith("PROBE:")), None)
    assert line, f"probe produced no output for {page}:\n{out.stdout}\n{out.stderr}"
    return json.loads(line[len("PROBE:"):])


def test_litellm_reqs_kpi_switches_on_requests_basis():
    """Behavioural counterpart to the static check: renderKpis() must print
    "Reqs (today)" when the collector says the count is a UTC day total, and keep
    "Reqs (win)" for a real rolling window — including when `requests_basis` is absent
    entirely (older snapshot / off mode), which must not regress to the day wording."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {};
    const base = { available:true, backlog:0, tokens_today:1000 };
    renderKpis(Object.assign({}, base, {requests_window:52, requests_basis:"today_utc"}));
    out.lite = REG["ll-kpis"].innerHTML;
    renderKpis(Object.assign({}, base, {requests_window:7, requests_basis:"window"}));
    out.full = REG["ll-kpis"].innerHTML;
    renderKpis(Object.assign({}, base, {requests_window:3}));   // basis absent
    out.absent = REG["ll-kpis"].innerHTML;
    console.log("PROBE:" + JSON.stringify(out));
    """)
    assert "Reqs (today)" in seen["lite"] and "52" in seen["lite"]
    assert "Reqs (win)" in seen["full"] and "Reqs (today)" not in seen["full"]
    # missing basis must fall back to the window wording, never the day wording
    assert "Reqs (win)" in seen["absent"] and "Reqs (today)" not in seen["absent"]


def test_by_user_charts_never_show_a_key_id():
    """A 'by user' chart must show USERS, never a key id. A key whose owner LiteLLM never
    resolved (no email) used to fall back to its own key label in `userOf`; it now groups
    under 'Unassigned' (matching the Settings board + the Spend page's 'Cost by user'). A key
    WITH a resolved owner still shows the username (email local part)."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {};
    // budgets carry the resolved owner email for 'alice-key' only; 'orphan-key' has none
    buildKeyUser({keys:[{key:"alice-key", email:"alice.smith@example.com"},
                        {key:"orphan-key", email:""}]});
    out.resolved   = userOf("alice-key");     // → "alice.smith" (username)
    out.unresolved = userOf("orphan-key");    // → "Unassigned" (NOT "orphan-key")
    out.unknown    = userOf("some-hash-abc"); // → "Unassigned" (NOT the key id)
    console.log("PROBE:" + JSON.stringify(out));
    """)
    assert seen["resolved"] == "alice.smith", seen
    assert seen["unresolved"] == "Unassigned", f"unresolved key must not show its id: {seen}"
    assert seen["unknown"] == "Unassigned", f"unknown key must not show its id: {seen}"
    # and the card copy no longer promises the old key-id fallback
    html = _page("litellm")
    assert "shown by its key" not in html
    assert 'group under "Unassigned"' in html

    # The Concurrent-work / Backlog "by user" cards get per-KEY bands from the server; the
    # fold groups them by owner so a key id can NEVER surface. Two of alice's keys merge into
    # one 'alice.smith' band; an ownerless key becomes 'Unassigned'; the server's 'Other' stays.
    folded = _probe_page_js("litellm.html", r"""
    buildKeyUser({keys:[{key:"alice-a", email:"alice.smith@example.com"},
                        {key:"alice-b", email:"alice.smith@example.com"},
                        {key:"bob-1",   email:"bob@example.com"}]});
    const series=[{label:"alice-a", data:[1,2]}, {label:"alice-b", data:[3,4]},
                  {label:"bob-1", data:[5,null]}, {label:"orphan-xyz", data:[1,1]},
                  {label:"Other", data:[9,9]}];
    const out=_foldSeriesByUser(series);
    console.log("PROBE:"+JSON.stringify({
      labels: out.map(s=>s.label),
      alice:  (out.find(s=>s.label==="alice.smith")||{}).data,   // [4,6] (1+3, 2+4)
    }));
    """)
    labels = folded["labels"]
    assert "alice.smith" in labels and "bob" in labels, f"owners must show as bands: {labels}"
    assert "Unassigned" in labels, f"ownerless key must fold to Unassigned: {labels}"
    assert labels[-1] == "Other", f"server residual 'Other' must stay last: {labels}"
    # NO raw key id may appear as a band label
    for kid in ("alice-a", "alice-b", "bob-1", "orphan-xyz"):
        assert kid not in labels, f"'by user' fold leaked a key id: {kid} in {labels}"
    assert folded["alice"] == [4, 6], f"alice's two keys must sum element-wise: {folded['alice']}"


def test_charts_omit_all_zero_series_from_the_legend():
    """A series whose values are ALL zero/null must not become a chart dataset — Chart.js builds
    the legend from its datasets, so a flat-zero band (e.g. a user with keys but no activity in
    the window on 'Concurrent LLM work — by user') would otherwise show a dead legend entry and
    an invisible line. Runtime-probes the shared `_nzLabels` helper and guards each builder's
    filter so it can't silently regress."""
    out = _probe_page_js("litellm.html", r"""
    const pts=[{a:1,b:0,c:null},{a:2,b:0,c:0}];      // a has real values; b, c are flat zero/null
    console.log("PROBE:"+JSON.stringify({kept:_nzLabels(["a","b","c"], pts)}));
    """)
    assert out["kept"] == ["a"], f"_nzLabels must drop all-zero/all-null keys: {out}"
    html = _page("litellm")
    # stacked attribution charts (conc/backlog by user/model/key) drop all-zero bands, incl. Other
    assert "(d.series||[]).filter(s=>(s.data||[]).some(v=>v!=null && v!==0))" in html, \
        "renderStackByKey must drop all-zero bands before building datasets"
    # the per-user delta chart drops flat-zero users
    assert "drop flat-zero users" in html, "loadUserDelta must drop users whose series is all zero"
    # the keytime + keydelta line charts route their labels through the shared filter
    assert html.count("_nzLabels(") >= 3, "keydelta/keytime charts must filter all-zero keys"


def test_litellm_top_key_bars_badge_cumulative_spend_in_lite():
    """The two top-key bars rank by CUMULATIVE lifetime spend in lite mode (LiteLLM
    /global/spend/keys has no per-key requests), so the rolling "last Nm" badge was
    doubly wrong there. Behavioural check on both bars via keysBadge()."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {};
    const keys = [{key:"h1", alias:"team-a", reqs:null, cost:9.26}];
    renderKeys({available:true, spend_mode:"lite", spend_window_min:15, top_keys:keys});
    out.liteKeys = REG["keys-win"].textContent;
    renderUserKeys({available:true, spend_mode:"lite", spend_window_min:15, top_keys:keys});
    out.liteUsers = REG["userkeys-win"].textContent;
    renderKeys({available:true, spend_mode:"full", spend_window_min:15,
                top_keys:[{key:"h1", alias:"team-a", reqs:12, cost:1.0}]});
    out.fullKeys = REG["keys-win"].textContent;
    console.log("PROBE:" + JSON.stringify(out));
    """)
    assert seen["liteKeys"] == "all time cumulative spend"
    assert seen["liteUsers"] == "all time cumulative spend"
    assert seen["fullKeys"] == "last 15m"


def test_litellm_delta_cards_relabel_to_spend_in_lite_mode():
    """In lite/off spend mode the key_series column holds per-key SPEND (the collector
    reports reqs=None and db.insert_key_series falls back to cost), so the
    '\u2026 \u2014 requests in window' cards are drawing currency. Executing the page JS must
    show labelDeltaCard() retitling heading, sub-line and aria-label to 'spend' when
    _spendMode != 'full', and leaving 'requests' alone in full mode."""
    seen = _probe_page_js("litellm.html", r"""
    const seen = {};
    _spendMode = "lite";
    labelDeltaCard("keydelta"); labelDeltaCard("userdelta");
    seen.liteKeyMetric  = REG["keydelta-metric"].textContent;
    seen.liteUserMetric = REG["userdelta-metric"].textContent;
    seen.liteKeySub     = REG["keydelta-sub"].textContent;
    seen.liteAria       = REG["keydelta-chart"].getAttribute("aria-label");
    _spendMode = "full";
    labelDeltaCard("keydelta"); labelDeltaCard("userdelta");
    seen.fullKeyMetric  = REG["keydelta-metric"].textContent;
    seen.fullUserMetric = REG["userdelta-metric"].textContent;
    seen.fullKeySub     = REG["keydelta-sub"].textContent;
    seen.fullAria       = REG["keydelta-chart"].getAttribute("aria-label");
    console.log("PROBE:" + JSON.stringify(seen));
    """)
    # lite -> spend everywhere, and the sub-line explains WHY (no per-key request counts)
    assert seen["liteKeyMetric"] == "spend" and seen["liteUserMetric"] == "spend"
    assert "spend" in seen["liteKeySub"] and "request counts" in seen["liteKeySub"]
    assert "spend" in seen["liteAria"].lower()
    # full -> the original request wording is preserved
    assert seen["fullKeyMetric"] == "requests" and seen["fullUserMetric"] == "requests"
    assert "cumulative requests" in seen["fullKeySub"]
    assert "requests" in seen["fullAria"].lower()


def test_wlabel_never_leaks_the_raw_custom_token():
    """Unit-level behavioural pin of wlabel() itself (bug-registry class #3/#4): a raw
    'custom:<secs>' window token must never reach the UI as user-visible text — wlabel()
    is the single choke point every window badge on the page is supposed to render
    through. Guards the underlying utility all call sites (including loadKeyTimeWin,
    registry #18) depend on, not just one call site's wiring."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {
      custom900: wlabel("custom:900"),
      custom1:   wlabel("custom:1"),
      plain1h:   wlabel("1h"),
      plain24h:  wlabel("24h"),
    };
    console.log("PROBE:" + JSON.stringify(out));
    """)
    assert seen["custom900"] == "custom" and "900" not in seen["custom900"]
    assert seen["custom1"] == "custom" and ":1" not in seen["custom1"]
    # non-custom tokens pass through unchanged — wlabel must not mangle ordinary windows
    assert seen["plain1h"] == "1h"
    assert seen["plain24h"] == "24h"


def test_load_key_time_win_renders_the_window_badge_through_wlabel():
    """End-to-end behavioural regression for bug-registry #18: loadKeyTimeWin() used to set
    the windowed 'Top 10 API keys over time' card's badge with the RAW WIN token
    (w.textContent=WIN) instead of routing it through wlabel() like every other window
    badge on the page — a custom drag-to-zoom selection would show 'custom:900' verbatim.
    Executes the real async loader (fetch is stubbed) and reads the actual DOM text set,
    catching a regression to the raw assignment even if it dodges a static string scan."""
    seen = _probe_page_js("litellm.html", r"""
    (async () => {
      WIN = "custom:900";
      await loadKeyTimeWin();
      const out = { badge: REG["keytimewin-win"].textContent };
      console.log("PROBE:" + JSON.stringify(out));
    })();
    """)
    assert seen["badge"] == "custom", f"raw window token leaked into the badge: {seen}"
    assert "900" not in seen["badge"]


def test_litellm_lite_requests_kpi_is_labelled_today_not_window():
    """Lite mode's requests count is the UTC day-to-date total from /global/activity,
    not a rolling window — an idle proxy otherwise reads as permanently busy under a
    'last 15m' badge. The collector declares requests_basis and the KPI honours it."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert 'l.requests_basis==="today_utc"' in html, "KPI must switch on requests_basis"
    assert '"Reqs (today)"' in html and '"Reqs (win)"' in html
    # the two top-key bars rank by CUMULATIVE spend in lite mode, so the "last Nm"
    # badge is wrong there too
    assert "function keysBadge(" in html
    assert '"cumulative spend"' in html
    src = (ROOT / "collectors" / "litellm.py").read_text(encoding="utf-8")
    assert 'out["requests_basis"] = "today_utc"' in src
    assert 'res["requests_basis"] = "window"' in src


def test_services_toggle_tunables_and_bool_ui():
    """Settings → Services exposes a per-backend monitor on/off for litellm/ollama/
    llamacpp/vllm as bool tunables, and the Settings page renders bool as an On/Off
    control (it previously only rendered number/choice, so bool tunables were invisible)."""
    import config
    for name in ("LITELLM_ENABLED", "OLLAMA_ENABLED", "LLAMACPP_ENABLED", "VLLM_ENABLED"):
        assert name in config.TUNABLES, f"{name} tunable missing"
        assert config.TUNABLES[name]["t"] == "bool" and config.TUNABLES[name]["group"] == "Services"
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    assert 's.type==="bool"' in html, "settings page must render bool tunables"
    assert re.search(r'\["1","On"\]', html) and re.search(r'\["0","Off"\]', html)


def test_by_key_stack_cards_show_empty_state_instead_of_vanishing():
    """Live regression: switching /litellm to 15m/1h made "Concurrent LLM work — by key"
    and "LLM Backlog — by key" DISAPPEAR. In lite/off mode the split is weighted by each
    key's per-bucket spend delta, so an idle window legitimately yields no bands and the
    server returns an empty series — but the page then set the whole card to
    display:none, so the section vanished and the page reflowed around it, which reads
    as a broken chart. The card must stay visible and state that there's no activity."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {};
    const EMPTY = {labels: [], series: [], weight_basis: "spend"};
    const FULL  = {labels: [1, 2], weight_basis: "spend",
                   series: [{label: "team-a", data: [1, 2]}]};
    renderStackByKey(EMPTY, concByKeyChart, "card-conc-by-key", "conc-by-key-basis");
    out.emptyCard  = REG["card-conc-by-key"].style.display;
    out.emptyWrap  = REG["conc-by-key-wrap"].style.display;
    out.emptyMsg   = REG["conc-by-key-empty"].style.display;
    out.emptyBadge = REG["conc-by-key-basis"].textContent;
    renderStackByKey(FULL, concByKeyChart, "card-conc-by-key", "conc-by-key-basis");
    out.fullCard   = REG["card-conc-by-key"].style.display;
    out.fullWrap   = REG["conc-by-key-wrap"].style.display;
    out.fullMsg    = REG["conc-by-key-empty"].style.display;
    out.fullBadge  = REG["conc-by-key-basis"].textContent;
    // the sibling backlog card shares the same renderer and must behave identically
    renderStackByKey(EMPTY, backlogByKeyChart, "card-backlog-by-key", "backlog-by-key-basis");
    out.blCard = REG["card-backlog-by-key"].style.display;
    out.blMsg  = REG["backlog-by-key-empty"].style.display;
    console.log("PROBE:" + JSON.stringify(out));
    """)
    # idle window: card stays, chart hidden, message shown
    assert seen["emptyCard"] != "none", "by-key card must not vanish on an idle window"
    assert seen["emptyWrap"] == "none", "chart canvas should be hidden when there's no data"
    assert seen["emptyMsg"] != "none", "empty-state message must be shown"
    assert seen["emptyBadge"] == "", "basis badge should clear when nothing is attributed"
    # data present: chart back, message gone
    assert seen["fullCard"] != "none" and seen["fullWrap"] != "none"
    assert seen["fullMsg"] == "none"
    assert "estimated" in seen["fullBadge"]
    # sibling behaves the same
    assert seen["blCard"] != "none" and seen["blMsg"] != "none"


def test_by_key_empty_state_text_is_present_for_both_cards():
    """Every stacked concurrency/backlog card ships the empty-state element the renderer
    toggles, with non-empty text (the exact wording is free to change — the cards were
    relabelled by-user/by-model, so this pins the elements + that they carry a message,
    not a specific string)."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    for cid in ("conc-by-key", "backlog-by-key", "conc-by-model"):
        assert f'id="{cid}-wrap"' in html, f"{cid} chart wrapper missing"
        m = re.search(r'id="' + cid + r'-empty"[^>]*>([^<]+)<', html)
        assert m and m.group(1).strip(), f"{cid} empty-state missing or blank"


def test_settings_unassigned_group_has_a_show_hide_switch():
    """Settings → the Unassigned group (every key LiteLLM reports no owner for) carries a
    Show | Hide segmented control wired to the HIDE_UNASSIGNED_KEYS tunable, and only that
    group does — a real user's row must not grow a visibility control."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    assert "HIDE_UNASSIGNED_KEYS" in html, "settings page must know the tunable"
    assert "_hideUnassigned" in html, "live value must be mirrored for the button state"
    # the control is built inside the `unassigned` branch, not for every user block
    i_branch = html.index("if(unassigned){")
    i_post = html.index('name:"HIDE_UNASSIGNED_KEYS"')
    assert i_branch < i_post, "the control must live in the unassigned-only branch"
    assert 'aria-pressed' in html, "active side must be exposed assistively"
    # two explicit buttons, not a blind toggle: distinct Show and Hide
    assert 'bShow.textContent="Show"' in html and 'bHide.textContent="Hide"' in html
    # it MUST post the shape the /api/admin/settings handler accepts —
    # action=set&name=&value= — not a bare {NAME: value} (which the server rejects as
    # "unknown setting", so the button clicked but nothing changed). Regression guard.
    assert re.search(
        r'post\(\{action:"set",\s*name:"HIDE_UNASSIGNED_KEYS",\s*value:', html), \
        "switch must post {action:'set', name:'HIDE_UNASSIGNED_KEYS', value:…}"
    assert 'post({HIDE_UNASSIGNED_KEYS:' not in html, \
        "must NOT post a bare {NAME: value} — the server rejects it as 'unknown setting'"
    # the active side is highlighted so the CURRENT state is visible at a glance
    assert '.uvis.on{' in html, "active side must have a highlighted style"
    # NOTE: settings.html wraps its JS in an IIFE, so userBlock() is not reachable from
    # the node probe harness the way litellm.html's helpers are. This stays a structural
    # test rather than exposing page internals purely to make them testable.


def test_hide_unassigned_tunable_is_not_rendered_as_a_settings_card():
    """HIDE_UNASSIGNED_KEYS is served for its value (env default + persistence + the
    Show/Hide button's live state all read it) but must NOT render as its own settings
    card — that card duplicated the button. It carries card=False, tunables_view()
    exposes that, and render() drops non-card tunables."""
    import config
    assert config.TUNABLES["HIDE_UNASSIGNED_KEYS"].get("card") is False, \
        "the tunable must be flagged non-card"
    view = {t["name"]: t for t in config.tunables_view()}
    assert view["HIDE_UNASSIGNED_KEYS"]["card"] is False, "tunables_view must carry card"
    # every normal tunable still defaults to being a card
    assert view["SAMPLE_INTERVAL"]["card"] is True
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    assert "s.card!==false" in html, "render() must skip non-card tunables"


def test_model_token_types_endpoint_and_collector_are_wired():
    """1.8.8: the per-model token-type split (input/cached/output) is exposed by an admin route
    backed by a heavy /spend/logs collector, and the per-type cost setter is volume-aware."""
    app_src = (ROOT / "app.py").read_text(encoding="utf-8")
    coll_src = (ROOT / "collectors" / "litellm.py").read_text(encoding="utf-8")
    db_src = (ROOT / "db.py").read_text(encoding="utf-8")
    # admin-gated GET route registered (the /api/admin/* prefix enforces admin at middleware)
    assert 'add_get("/api/admin/model-token-types"' in app_src
    assert "async def api_admin_model_token_types_handler" in app_src
    # collector pulls /spend/logs (the only source with the prompt/completion/cache split),
    # DAY-BY-DAY (start_date=D&end_date=D) so each request stays under the byte cap
    assert "async def per_model_token_types" in coll_src
    assert "/spend/logs?start_date={ds}&end_date={ds}" in coll_src
    assert "days_failed" in coll_src            # per-day failures surfaced, not swallowed
    assert "def _fold_model_token_types" in coll_src and "def _row_cached_tokens" in coll_src
    # volume-weighted blend is wired end to end
    assert "vol_in" in app_src and "vol_out" in app_src and "vol_cache" in app_src
    assert "def _blend_1m" in db_src and "vin" in db_src and "vcache" in db_src


def test_model_costs_is_an_aligned_grid_with_a_shared_header():
    """The MODEL COSTS card was a ragged flex row: each in/out/cache cell stacked its label
    OVER its value (`flex-direction:column`) and floated, and the override input drifted, so
    nothing lined up row-to-row. It is now a grid — a header row (.mhdr) labels in/out/cache/
    override ONCE and every model row (.srow.tmodel) right-aligns its values in those columns.
    The header and the rows MUST share the exact same column template or they would not line
    up; that shared rule is the alignment invariant."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    # header and rows are declared in ONE combined rule → identical tracks by construction
    m = re.search(r"\.srow\.tmodel,\.mhdr\{grid-template-columns:([^;]+);", html)
    assert m, "the .srow.tmodel + .mhdr shared grid rule is missing"
    tracks = m.group(1).split()
    assert len(tracks) == 6, f"expected 6 columns (name·kind·in·out·cache·actions), got {tracks}"
    # the header exists and labels every numeric column
    assert 'className="mhdr"' in html or 'class="mhdr"' in html or '"mhdr"' in html, "no header row"
    assert '.mhdr{display:grid' in html, "header must use the same grid"
    for col in ('"in"', '"out"', '"cch"'):
        assert col in html, f"header is missing the {col} column label"
    # the old ragged structure is gone (no per-cell label-over-value flex column)
    assert ".mcosts" not in html and 'class="mc"' not in html, \
        "the old floating .mcosts/.mc cell structure must be removed"


def test_model_costs_grid_actions_column_is_fixed_not_auto():
    """Alignment bug guard: the actions (✓ ↺) column MUST be a fixed width, not `auto`. An
    `auto` track is 0-wide in the header (its cell is empty) but ~64px in a data row (the
    buttons), so the flexible name column would absorb different slack and the numeric columns
    would NOT line up between the header and the rows."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    m = re.search(r"\.srow\.tmodel,\.mhdr\{grid-template-columns:([^;]+);", html)
    assert m, "shared grid rule missing"
    last = m.group(1).split()[-1]
    assert last != "auto", "the actions column must be a fixed width, not auto (breaks alignment)"
    assert re.match(r"^\d+px$", last), f"actions column should be a fixed px width, got {last!r}"
    # save + reset ride in ONE actions cell so they occupy a single grid column
    assert 'acts.className="macts"' in html or 'class="macts"' in html, "actions must share one cell"
    assert ".macts{" in html, "the actions cell needs its own layout rule"


def test_model_costs_row_children_match_the_header_cells():
    """A grid only aligns if every row has the same number of direct children as the header
    has cells (7). modelRow must append, in column order: name · kind select · in · out ·
    cache · override input · actions — the three rates as DIRECT cells (not wrapped), so they
    land in their own columns."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    start = html.index("function modelRow(")
    body = html[start:html.index("\n  function ", start + 1)]
    # the three rates are EDITABLE cells built by mcellEdit, each with its own tooltip;
    # eff is a read-only cell. All are DIRECT row children so they land in their columns.
    assert "mcellEdit(m.in_1m, MCOL_TIP.in" in body
    assert "mcellEdit(m.out_1m, MCOL_TIP.out" in body
    assert "mcellEdit(m.cache_1m, MCOL_TIP.cache" in body
    # exactly six direct grid children, in order: name · kind · in · out · cache · actions
    # (the effective blended cost lives in the model-name popover, not a column, so the
    # ✓/↺ actions stay visible in the narrow card)
    kids = re.findall(r"row\.appendChild\(([^)]+)\)", body)
    assert kids == ["lbl", "sel", "inC", "outC", "cacheC", "acts"], kids


def test_model_costs_refresh_never_blanks_the_card():
    """Regression: a per-row refresh (✓/↺) and the top 'Refresh from LiteLLM' both funnel
    through loadModels(), which used to `el.textContent=""` BEFORE the fetch resolved — so a
    slow/empty/flaky re-pull (or a swallowed fetch error) left the whole card blank until a
    full page reload. loadModels now builds the rows in a fragment and swaps atomically, and an
    empty/failed refresh keeps the values already on screen."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    start = html.index("function loadModels(force)")
    body = html[start:html.index("\n  var _rb", start)]
    assert "createDocumentFragment()" in body, "must build the replacement off-screen"
    assert 'el.textContent=""; el.appendChild(frag)' in body, "must swap the card in atomically"
    # the ONLY blank of the card is that atomic swap — never a clear-before-fetch
    assert body.count('el.textContent=""') == 1, "card must not be cleared before data arrives"
    # an empty result on a populated card keeps the values (doesn't wipe to 'No models')
    assert "if(el.firstChild)" in body, "empty result must keep existing values"
    # a fetch error keeps values too; the admin-only hint only shows on an already-empty card
    assert 'if(!el.firstChild){ el.textContent="Model costs are admin-only."' in body
    # errors are no longer silently swallowed into a blank card
    assert ".catch(function(){});" not in body, "fetch errors must not be swallowed silently"


def test_model_costs_row_refresh_routes_through_loadModels():
    """The fix lives in loadModels(), so the per-row controls the user actually clicks — Save (✓)
    and Reset (↺) — must re-render via loadModels (not a separate path that could still wipe the
    card). Both handlers call loadModels after their POST completes, and they re-render WITHOUT
    forcing a LiteLLM re-pull (no ?refresh=1), so they use the cached last-good and can't blank
    the card on a flaky upstream."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    start = html.index("function modelRow(")
    body = html[start:html.index("\n  function loadModels(", start)]
    # Save and Reset both re-render through loadModels once their POSTs resolve
    assert body.count("loadModels") >= 2, "Save and Reset must re-render via loadModels()"
    # and they must NOT force a re-pull (loadModels() / loadModels with no truthy force) — a
    # per-row action re-renders from the cache, never a fresh (flaky) LiteLLM pull
    assert "loadModels(true)" not in body, "per-row refresh must not force a ?refresh=1 re-pull"
    # the top 'Refresh from LiteLLM' button IS the only forced re-pull
    assert 'addEventListener("click",function(){loadModels(true);})' in html \
        or "loadModels(true)" in html[html.index("models-refresh"):], \
        "the top Refresh button should be the only forced re-pull"


def test_model_name_click_opens_an_info_popover():
    """Clicking a model name opens an info popover with the full name, provider, parameter
    count (parsed from the name — MoE total·active aware), kind, 30d usage, and rates. The
    name is a keyboard-reachable button, the popover is position:fixed (so the card's
    overflow:auto can't clip it) and closes on an outside click or Escape, and every field is
    written via textContent (never an HTML sink)."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    # the name is interactive + wired to the popover
    assert 'lbl.setAttribute("role","button")' in html and 'lbl.setAttribute("tabindex","0")' in html, \
        "the model name must be a keyboard-reachable button"
    assert "openModelInfo(m,lbl)" in html, "clicking the name must open the info popover"
    assert 'lbl.addEventListener("keydown"' in html, "Enter/Space must also open it"
    # the popover builds the promised fields
    assert "function openModelInfo(" in html
    for field in ('"Provider"', '"Parameters"', '"30d usage"', '"Input"', '"Output"',
                  '"Cache read"', '"Effective"'):
        assert field in html, f"popover is missing the {field} row"
    # parameter parsing incl. the MoE total·active form vLLM models use
    assert "function paramSize(" in html and "function modelParams(" in html
    assert "B total · " in html and "B active" in html, "MoE total/active params not surfaced"
    # dismissable + not clipped
    assert ".mpop{" in html and "position:fixed" in html.split(".mpop{")[1][:80], \
        "popover must be position:fixed so the card overflow can't clip it"
    assert 'e.key==="Escape"' in html and "_mpopOut" in html, "must close on Escape / outside click"
    # security: no HTML sink for model-supplied strings — content is textContent only
    body = html[html.index("function openModelInfo("):html.index("function modelRow(")]
    assert "innerHTML" not in body, "popover must not use an innerHTML sink"


def test_model_param_parsing_is_correct_for_real_model_names():
    """Behavioural (not source-inspection): extract the popover's `paramSize` + `modelParams`
    from settings.html and RUN them in node against real model names. This is what actually
    verifies the parameter figure shown to the operator — a structural test only proves the
    function exists, not that `Qwen3-Coder-30B-A3B` reads as `30B total · 3B active`."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for JS behavioural test")
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")

    def _extract(fn):
        i = html.index("function " + fn + "(")
        depth, j = 0, i
        while j < len(html):
            if html[j] == "{":
                depth += 1
            elif html[j] == "}":
                depth -= 1
                if depth == 0:
                    return html[i:j + 1]
            j += 1
        raise AssertionError(f"could not extract {fn}")

    cases = [
        # MoE "total-Active" form vLLM/Qwen use → total · active
        ("vllm/Qwen3-Coder-30B-A3B-Instruct-NVFP4", "30B total · 3B active"),
        ("vllm/MiniMax-M2.5-REAP-139B-A10B-NVFP4", "139B total · 10B active"),
        # classic mixture-of-experts NxM
        ("mistralai/Mixtral-8x7B-Instruct", "8×7B"),
        # plain billions / fractional billions / millions
        ("meta-llama/Llama-3.1-70B-Instruct", "70B"),
        ("Qwen2.5-Coder-1.5B", "1.5B"),
        ("some/embed-model-270m", "270M"),
        # no parameter figure in the name → the em dash the popover shows
        ("azure_ai/gpt-5-mini", "—"),
        ("llama-cpp/Qwen3-Coder-Next", "—"),
    ]
    harness = _extract("paramSize") + "\n" + _extract("modelParams") + "\n"
    harness += "const C=" + json.dumps(cases) + ";\n"
    harness += ("let bad=[]; for(const [name,exp] of C){ const got=modelParams(name);"
                " if(got!==exp) bad.push(name+' => '+got+' (want '+exp+')'); }"
                " if(bad.length){ console.error(bad.join('\\n')); process.exit(1); }"
                " console.log('ok');")
    out = subprocess.run([node, "-e", harness], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, f"parameter parsing wrong:\n{out.stderr.strip()}"


def test_settings_unassigned_switch_does_not_break_the_row_grid():
    """.urow is a FIXED 5-column grid (uid | team | budget | actions | keys). Appending the
    visibility switch straight onto the row made it a 6th direct child, which silently took
    the 150px team column and shoved every later cell one slot right — the key strip wrapped
    onto its own line below. The switch must go INSIDE the actions cell instead, keeping the
    row at exactly five children."""
    html = (ROOT / "web" / "settings.html").read_text(encoding="utf-8")
    # the grid still declares five tracks
    m = re.search(r"\.urow\{display:grid;grid-template-columns:([^;]+);", html)
    assert m, "could not find the .urow grid definition"
    assert len(m.group(1).split()) == 5, f"expected 5 grid tracks, got {m.group(1)!r}"
    # the switch is appended to the actions container, never directly to the row
    assert "if(vis) btns.appendChild(vis);" in html, "switch must ride in the actions cell"
    assert "row.appendChild(vis)" not in html, "switch must NOT be a direct grid child"
    # exactly the five intended direct children of .urow, in order
    start = html.index("function userBlock(")
    body = html[start:html.index("\n  function ", start + 1)]
    kids = re.findall(r"row\.appendChild\((\w+)\)", body)
    assert kids == ["uname", "teamcell", "bud", "btns", "strip"], kids
    # the control is a segmented Show|Hide group with its own sizing class (not a bare
    # .ib, which is icon-sized)
    assert 'vis.className="uvis-grp"' in html and ".uvis-grp{" in html


def test_every_snapshot_serving_endpoint_applies_the_key_visibility_filter():
    """The rule must hold on EVERY page, which means every endpoint that ships the live
    LiteLLM snapshot has to pass it through _snapshot_for_display: /api/data (all the
    dashboards poll it), the SSE /api/stream (same data, different transport — a page on
    the stream would otherwise see the unfiltered list), and /api/budgets via
    _visible_top_keys (the Spend page's cost-by-key, by-team and per-key budgets).

    Storage and the admin board are deliberately NOT filtered — history must stay
    complete, and unassigned keys must remain assignable in Settings."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    # /api/data still passes _latest through the key-visibility filter; it may be wrapped
    # (e.g. _redact_containers(...) for the F-2 container-name gate), so match the filter call
    # applied to _latest rather than the exact surrounding literal.
    assert '"latest": ' in src and "_snapshot_for_display(_latest)" in src, "/api/data unfiltered"
    # /api/stream passes _latest through the SAME filter, wrapped in _redact_containers so the
    # SSE feed also honours the F-2 container-name gate (a viewer streaming here must not see
    # host topology that /api/data hides).
    assert "_disp = _redact_containers(_snapshot_for_display(_latest)" in src, \
        "/api/stream must filter AND redact the snapshot"
    assert "merge_key_budgets(live, _visible_top_keys(" in src, "/api/budgets unfiltered"
    # storage keeps every key — the read paths filter at query time instead
    assert 'db.insert_key_series(snap["ts"], _ll.get("top_keys") or [])' in src, \
        "stored history must NOT be pre-filtered"


def test_overview_kpis_use_prefilter_totals():
    """Hiding a key removes its bar, never a measured total: the Overview's spend and key
    KPIs must prefer the pre-filter aggregates the display filter carries."""
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert "l.cost_all_keys!=null" in html, "spend KPI must use the pre-filter total"
    assert "l.keys_total!=null" in html, "key count must use the pre-filter count"


def test_litellm_windowed_spend_cards_and_layout():
    """LiteLLM page: two new 'spend in window' cards (keys + users) follow the page window via
    /api/spend/keycost; the all-time 'by requests' pair is moved to the bottom and swapped
    (users before keys), and its badge now reads 'all time cumulative spend'."""
    html = _page("litellm")
    # the two new windowed-spend cards exist and are wired to the windowed keycost endpoint
    assert 'id="card-keys-winspend"' in html and 'id="card-userkeys-winspend"' in html, \
        "the two windowed-spend cards must exist"
    assert 'id="keys-winspend-chart"' in html and 'id="userkeys-winspend-chart"' in html
    assert '"/api/spend/keycost?window="+WIN' in html, "windowed cards must follow the page window"
    assert "function loadWinSpend(" in html
    # loaded on the tick AND on a window change (rangedReload)
    assert "loadUserDelta(); loadWinSpend();" in html, "loadWinSpend must be in the reload path"
    assert "await loadWinSpend();" in html, "loadWinSpend must run on the tick too"
    # the badge rename
    assert 'return "all time cumulative spend";' in html
    assert 'return "cumulative spend";' not in html
    # the by-requests pair is moved BELOW the full-width charts card, swapped (users then keys)
    i_charts = html.index('id="card-charts"')
    i_users = html.index('id="card-userkeys"')
    i_keys = html.index('id="card-keys"')
    assert i_charts < i_users < i_keys, \
        "the all-time by-requests pair must sit at the bottom, users before keys"
    # and the NEW windowed cards sit near the top (before the moved originals)
    assert html.index('id="card-keys-winspend"') < i_users


def test_litellm_windowed_keys_over_time_card():
    """A windowed twin of "Top 10 API keys over time" sits where the all-time card used to
    be (following the page time-window selector via /api/keyseries), and the ALL-TIME card
    moved to 3rd-from-last. Both charts, their loaders, and the refresh wiring must exist."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    # both cards present, each with its own chart canvas
    assert 'id="card-keytime-win"' in html and 'id="keytime-win-chart"' in html
    assert 'id="card-keytime"' in html and 'id="keytime-chart"' in html
    # the windowed one is placed BEFORE the all-time one in the DOM (it took the old slot)
    assert html.index('id="card-keytime-win"') < html.index('id="card-keytime"')
    # the all-time card sits near the end (4th from last since the users-over-time card was
    # appended after it) — position anchor, not a hard 3rd-from-last, so a new trailing card
    # doesn't falsely fail this.
    order = re.findall(r'<section class="card[^"]*" id="(card-[a-z0-9-]+)"', html)
    assert order[-4] == "card-keytime", f"keytime must sit near the end, order tail={order[-4:]}"
    # windowed loader follows the selector (WIN) via the per-window key series endpoint,
    # and is TDZ-safe (its metric var declared before its chart)
    assert 'api("/api/keyseries?window="+WIN)' in html, "windowed card must follow WIN"
    assert html.index("let _keytimewinMetric") < html.index("keyTimeWinChart = new Chart")
    # refreshed on every reload path the other windowed charts use
    assert html.count("loadKeyTimeWin()") >= 3, "must run on rangedReload + window change + init"
    # the all-time card still uses the all-time endpoint (unchanged), so the two differ
    assert 'api("/api/keyrequests")' in html, "all-time card keeps the all-time source"


def test_litellm_concurrency_by_model_card():
    """A 'Concurrent LLM work — by model' stacked card sits right after the by-user one,
    fetching the same aggregate split by model (by=model), wired into the refresh cycle."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert 'id="card-conc-by-model"' in html and 'id="conc-by-model-chart"' in html
    assert "Concurrent LLM work — by model" in html
    # placed immediately after the by-user (conc-by-key) card, before the backlog card
    i_key = html.index('id="card-conc-by-key"')
    i_model = html.index('id="card-conc-by-model"')
    i_backlog = html.index('id="card-backlog-by-key"')
    assert i_key < i_model < i_backlog, "by-model card must sit between by-user and backlog"
    # loader hits the shared endpoint with by=model and is refreshed everywhere the by-key
    # one is (rangedReload + window change + initial)
    assert 'concurrency-by-key?metric=conc&by=model' in html
    assert html.count("loadConcByModel()") >= 3
    # reuses the generic stack renderer + its own empty-state element
    assert 'id="conc-by-model-empty"' in html and "no per-model activity" in html


def test_shared_core_module_dedups_api_across_pages_d3():
    """REVIEW D-3: the byte-identical `api()` (its pan/zoom `end=` append drifted between ~9
    per-page copies) is extracted to one self-hosted `aimon-core.js` that every page loads via
    a CSP-clean <script src>. The inline copy is gone from every page."""
    core = (ROOT / "web" / "assets" / "aimon-core.js").read_text(encoding="utf-8")
    assert "async function api(path)" in core, "the shared api() must live in the module"
    # the module guards TIMEEND so the Spend page (no pan cursor) doesn't ReferenceError
    assert 'typeof TIMEEND!=="undefined"' in core
    assert 'path.indexOf("window=")>=0' in core          # the pan/zoom end= append, once
    for name in ("index", "gpu", "ollama", "llamacpp", "network", "vllm", "litellm", "spend"):
        html = _page(name)
        assert '<script src="/assets/aimon-core.js"></script>' in html, f"{name}: must load core"
        assert "async function api(path)" not in html, f"{name}: inline api() must be removed"
    # D-3 (rest): the per-page time-window + pan/zoom helpers (identical across every WIN page,
    # a proven copy-paste drift source) are extracted to the same module. Each is defined ONCE
    # in core and no longer redefined inline on any WIN page.
    WIN_HELPERS = ("wsecs", "_winKey", "_winCustom", "_winSave", "_winRestore",
                   "_winMark", "wlabel", "stampTs")
    for fn in WIN_HELPERS:
        assert core.count(f"function {fn}(") == 1, f"core: {fn}() must be defined exactly once"
    assert "drag-to-zoom: drag across ANY chart" in core, "core: drag-zoom handler must live here"
    for name in ("index", "gpu", "ollama", "llamacpp", "network", "vllm", "litellm"):
        html = _page(name)
        for fn in WIN_HELPERS:
            assert f"function {fn}(" not in html, \
                f"{name}: {fn}() must not be redefined inline (single source is aimon-core.js)"
        # the page keeps only the CALL that supplies its own default window
        assert '_winRestore("#windows"' in html, f"{name}: must still call the shared _winRestore"
    # spend deliberately keeps its OWN coarser persistence, named _spWin* so it never clashes
    sp = _page("spend")
    for fn in WIN_HELPERS:
        assert f"function {fn}(" not in sp, f"spend: {fn}() must not shadow the shared core"
    assert "function _spWinRestore(" in sp, "spend: its own coarser persistence must be _spWin*"
    # published (else it 404s on a fresh clone). publish-github.sh is itself intentionally NOT
    # in the public repo, so skip this assertion when it isn't vendored (e.g. CI on the public
    # checkout) — matches the other publish-ALLOW-list tests.
    pub = ROOT / "deploy" / "publish-github.sh"
    if pub.exists():
        assert "web/assets/aimon-core.js" in pub.read_text(encoding="utf-8"), \
            "aimon-core.js must be in the publish ALLOW-list"


def test_by_key_stack_cards_have_clickable_why_other_explainer():
    """The stacked by-key/user/model cards get a clickable "why 'Other'?" link that opens a
    popover explaining the attribution gap (measured aggregate vs per-entity activity from a
    slower cadence) and names the active bands — so an operator can see why work landed in
    'Other' instead of a specific model/user."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    # the shared popover element + the link builder + its trigger from the renderer
    assert 'id="other-pop"' in html, "shared Other popover element missing"
    assert "function _wireWhyOther(" in html
    assert "_wireWhyOther(cardId, d)" in html, "renderStackByKey must wire the explainer"
    # link shows ONLY when an Other band actually exists
    assert 'series.find(s=>s.label==="Other")' in html
    assert '.whyother{' in html
    # popover content: reads the server attribution summary, states the cadence reason,
    # names the active bands, and distinguishes hidden-beyond-top-N from pure unattributed
    assert "d.attribution" in html
    assert "couldn’t be tied to a" in html
    # names the models folded into Other (not just a count) — "models being used there"
    assert "at.other_labels" in html and "Also in " in html
    assert "polled every" in html and "~5s" in html
    assert "Active " in html and "s here:" in html
    # backend supplies the attribution summary the popover reads
    src = (ROOT / "db.py").read_text(encoding="utf-8")
    assert '"attribution":' in src and '"labels_total"' in src and '"shown"' in src


def test_legend_full_names_info_recovers_truncated_labels():
    """Long legend labels (key hashes / long model names) are truncated to first8…last4.
    A clickable (i) per chart must reveal the FULL names. _legendFullRows (pure) recovers
    them from each line/stacked dataset's `_k`, and from a bar chart's `$full` array —
    returning only the entries that are actually truncated (short != full)."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {};
    // line/stacked chart: full name on dataset._k, truncated on .label
    const line = {data:{datasets:[
      {_k:"vllm/MiniMax-M2.5-REAP-139B-A10B-NVFP4-GB10", label:"vllm/Min…GB10"},
      {_k:"short", label:"short"} ]}};
    out.line = _legendFullRows(line, false);
    // bar chart: full names parallel to data.labels on $full
    const bar = {$full:["RodolfoSantos_ClaudeCode","x"], data:{labels:["Rodolfo…Code","x"]}};
    out.bar = _legendFullRows(bar, true);
    console.log("PROBE:" + JSON.stringify(out));
    """)
    # only the truncated line entry is returned, with its full name
    assert seen["line"] == [{"short": "vllm/Min…GB10",
                             "full": "vllm/MiniMax-M2.5-REAP-139B-A10B-NVFP4-GB10"}]
    # only the truncated bar entry, full name from $full
    assert seen["bar"] == [{"short": "Rodolfo…Code", "full": "RodolfoSantos_ClaudeCode"}]


def test_every_truncating_chart_has_a_full_names_info():
    """Every litellm chart whose legend truncates gets the (i) wired, and both bar charts
    store the full names ($full) the (i) reads."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert "function addLegendInfo(" in html and "function _legendFullRows(" in html
    for cid in ("card-keys", "card-userkeys",                      # the by-requests bars
                "card-keys-winspend", "card-userkeys-winspend", "card-keytime",
                "card-keytime-win", "card-keydelta", "card-userdelta",
                "card-conc-by-key", "card-conc-by-model", "card-backlog-by-key"):
        assert '"' + cid + '"' in html, f"{cid} not wired to addLegendInfo"
    # every bar chart must publish its full labels for the (i) — incl. the by-requests bars,
    # whose y-axis truncates long key/owner names
    for pub in ("keysChart.$full=", "userKeysChart.$full=",
                "keysWinSpendChart.$full=", "userWinSpendChart.$full="):
        assert pub in html, f"bar chart missing its full-label publish: {pub}"
    # the popover goes through the sanitized shared helper (single-sink invariant)
    assert "_showPop(ev, '<span class=\"x\">✕</span><h4>Full legend names" in html


def test_gpu_appcpu_has_full_names_info():
    """The GPU 'CPU usage by app' legend holds long process names. A clickable (i) lists
    their full names via the sanitized sink (single-innerHTML-sink invariant preserved)."""
    html = (ROOT / "web" / "gpu.html").read_text(encoding="utf-8")
    assert "function addAppLegendInfo(" in html and "addAppLegendInfo();" in html
    assert 'id="gpu-pop"' in html and ".appleg-i" in html
    assert "appCpuChart.data.datasets" in html, "(i) must read the live app datasets"
    # goes through the sanitized helper, not a raw second innerHTML sink
    assert "_gShowPop(ev," in html and "setHtml(_gpop," in html
    assert len(re.findall(r"innerHTML\s*=", html)) == 1, "gpu must keep ONE innerHTML sink"


def test_shortlbl_truncation_lives_in_one_place():
    """The first8…last4 truncation rule must exist exactly once, in aimon-core.js — not as
    N hand-copied versions per page (litellm.html used to carry 3: keyLabel, _shortLbl,
    keyDisp). Every page keeps working by calling the shared function."""
    core = _core_js()
    assert "function _shortLbl(" in core
    assert 's.slice(0,head)+"…"+s.slice(-tail)' in core
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    # litellm.html must no longer define its own copy of the slicing logic
    assert html.count('s.slice(0,8)+"…"+s.slice(-4)') == 0, (
        "litellm.html still hand-rolls the truncation instead of calling the shared _shortLbl()"
    )
    assert "function keyDisp(label){ return _shortLbl(label); }" in html


def test_hover_reveals_full_name_on_every_truncating_litellm_chart():
    """Every litellm.html chart that can show a shortened key/user/model name must reveal
    the FULL name on mouseover — not require a click on a separate (i) icon. Bar charts do
    this via a tooltip `title` callback reading `$full`; canvas-drawn legends (which have no
    real DOM node for a native `title` attribute) do it via the shared wireLegendFullName()
    hover-tooltip helper, keyed on each dataset's untruncated `_k`."""
    core = _core_js()
    for fn in ("showLblTip(", "hideLblTip(", "function wireLegendFullName("):
        assert fn in core, f"aimon-core.js missing {fn}"

    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    # bar charts: tooltip title callback must read the chart's own $full array, not the
    # (possibly truncated) axis label
    for chart_var in ("keysChart", "userKeysChart"):
        assert f"({chart_var}.$full||[])[i]" in html, (
            f"{chart_var}'s tooltip must show the full name on hover, not the truncated label"
        )
    assert "(ch.$full||[])[i]" in html, "_mkSpendBar's tooltip must show the full name on hover"

    # line/stacked charts: legend hover must be wired, keyed on the dataset's full name (_k)
    for chart_var in ("keyTimeChart", "keyTimeWinChart", "keyDeltaChart", "userDeltaChart"):
        assert f"wireLegendFullName({chart_var}," in html, (
            f"{chart_var} legend has no hover-to-reveal-full-name wiring"
        )
    # the 3 mkStackByKey-built charts (conc-by-key/model, backlog-by-key) share one factory
    assert "wireLegendFullName(ch," in html, "mkStackByKey charts have no legend hover wiring"

    # the value tooltip (hovering the plotted line, not just the legend) should also show
    # the full name — dataset._k falls back to dataset.label only when _k is absent
    for cb in (
        'label:c=>" "+(c.dataset._k||c.dataset.label)+": "+(_keytimeMetric',
        'label:c=>" "+(c.dataset._k||c.dataset.label)+": "+(_keytimewinMetric',
    ):
        assert cb in html, "keytime tooltip must prefer the full name (_k) over the truncated label"


def test_spend_truncated_text_has_title_fallback():
    """spend.html has two places where text can be cut off with no other way to see the
    rest: the 'keys used by X' detail-panel rows (CSS ellipsis) and the '(i) models could
    not be priced' note (deliberately truncated to 3 names). Both need a `title` carrying
    the untruncated text."""
    html = (ROOT / "web" / "spend.html").read_text(encoding="utf-8")
    assert 'class="ck" title="${escapeHtml(k.key)}"' in html, (
        "the 'keys used by X' row must carry the full key name as a title fallback"
    )
    assert 'title=\\""+escapeHtml(un.join(", "))+"' in html, (
        "the unpriced-models note must carry the FULL list as a title, not just the first 3"
    )


def test_shortlbl_runtime_truncation_boundaries():
    """RUNTIME proof of _shortLbl()'s exact behavior at its length boundaries — not just
    that the function exists (the static test above), but that it truncates the right
    strings the right way: keeps anything <=18 chars whole, shortens anything longer to
    head(8)…tail(4), and never chokes on null/undefined/numeric input."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {};
    out.shortUnchanged   = _shortLbl("exactly18chars12");     // 16 chars, under threshold
    out.exactlyAtLimit   = _shortLbl("123456789012345678");   // exactly 18 chars, untouched
    out.oneOverLimit     = _shortLbl("1234567890123456789");  // 19 chars, must truncate
    out.longKeyHash      = _shortLbl("sk-abcdefghijklmnopqrstuvwxyz0123456789");
    out.customHeadTail   = _shortLbl("abcdefghijklmnopqrstuvwxyz", 3, 2, 10);
    out.nullish          = _shortLbl(null);
    out.undef            = _shortLbl(undefined);
    out.numeric          = _shortLbl(12345);
    console.log("PROBE:" + JSON.stringify(out));
    """)
    assert seen["shortUnchanged"] == "exactly18chars12"
    assert seen["exactlyAtLimit"] == "123456789012345678", "exactly-18 must NOT be truncated (boundary is >18, not >=18)"
    assert seen["oneOverLimit"] == "12345678…6789", "19 chars must truncate to head(8)…tail(4)"
    assert seen["longKeyHash"] == "sk-abcde…6789"
    assert seen["customHeadTail"] == "abc…yz", "custom head/tail/threshold args must be honored"
    assert seen["nullish"] == "?"
    assert seen["undef"] == "?"
    assert seen["numeric"] == "12345"


def test_bar_chart_tooltip_title_shows_full_name_runtime():
    """RUNTIME proof: hovering a truncated bar (keysChart, userKeysChart, and both windowed
    spend bars built by _mkSpendBar) must show the FULL key/user name in the tooltip title,
    not Chart.js's default (the truncated axis label already sitting in data.labels)."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {};
    function titleFor(chart, dataIndex, fallbackLabel){
      const cb = chart.options.plugins.tooltip.callbacks.title;
      return cb([{ dataIndex, label: fallbackLabel }]);
    }
    keysChart.$full = ["a-very-long-api-key-alias-that-got-truncated"];
    keysChart.data.labels = ["a-very-l…ated"];
    out.keys = titleFor(keysChart, 0, "a-very-l…ated");

    userKeysChart.$full = ["someone.with.a.long.username"];
    userKeysChart.data.labels = ["someone.…name"];
    out.userKeys = titleFor(userKeysChart, 0, "someone.…name");

    keysWinSpendChart.$full = ["sk-anotherlongkeyhashvalue"];
    keysWinSpendChart.data.labels = ["sk-anoth…alue"];
    out.keysWinSpend = titleFor(keysWinSpendChart, 0, "sk-anoth…alue");

    userWinSpendChart.$full = ["yet.another.long.user.email"];
    userWinSpendChart.data.labels = ["yet.anot…mail"];
    out.userWinSpend = titleFor(userWinSpendChart, 0, "yet.anot…mail");

    // falls back to the label when $full has nothing for that index (out-of-range / unset)
    keysChart.$full = [];
    out.fallback = titleFor(keysChart, 0, "some-fallback-label");
    console.log("PROBE:" + JSON.stringify(out));
    """)
    assert seen["keys"] == "a-very-long-api-key-alias-that-got-truncated"
    assert seen["userKeys"] == "someone.with.a.long.username"
    assert seen["keysWinSpend"] == "sk-anotherlongkeyhashvalue"
    assert seen["userWinSpend"] == "yet.another.long.user.email"
    assert seen["fallback"] == "some-fallback-label", "must fall back to the axis label, not crash or show 'undefined'"


def test_legend_hover_shows_full_name_only_when_truncated_runtime():
    """RUNTIME proof of wireLegendFullName(): hovering a legend entry whose displayed text
    differs from its dataset's full name (_k) must show the floating tooltip with the full
    name; hovering one that ISN'T truncated (full === shown) must show nothing; leaving
    must always hide it. Exercises the real onHover/onLeave Chart.js wires into
    keyTimeChart, keyDeltaChart, and the shared mkStackByKey charts (conc-by-key)."""
    seen = _probe_page_js("litellm.html", r"""
    const out = {};
    const fakeEvt = { native: { clientX: 100, clientY: 50 } };
    function hoverAndRead(chart, datasetIndex, text){
      chart.data.datasets[datasetIndex] = Object.assign(
        {}, chart.data.datasets[datasetIndex], {});
      chart.options.plugins.legend.onHover(fakeEvt, { text, datasetIndex }, {});
      return { shown: _lblTipEl.style.display, text: _lblTipEl.textContent };
    }
    function leaveAndRead(chart, datasetIndex, text){
      chart.options.plugins.legend.onLeave(fakeEvt, { text, datasetIndex }, {});
      return _lblTipEl.style.display;
    }

    keyTimeChart.data.datasets = [{ _k: "alice@example.com (long alias)", label: "alice@e…lias)" }];
    out.truncatedHover = hoverAndRead(keyTimeChart, 0, "alice@e…lias)");
    out.truncatedLeave = leaveAndRead(keyTimeChart, 0, "alice@e…lias)");

    keyDeltaChart.data.datasets = [{ _k: "short-key", label: "short-key" }];
    out.untruncatedHover = hoverAndRead(keyDeltaChart, 0, "short-key");

    // shared mkStackByKey factory (conc-by-key-chart) — must be wired the same way
    concByKeyChart.data.datasets = [{ _k: "vllm/A-Very-Long-Model-Name-Here", label: "vllm/A-…Here" }];
    out.stackedHover = hoverAndRead(concByKeyChart, 0, "vllm/A-…Here");

    console.log("PROBE:" + JSON.stringify(out));
    """)
    assert seen["truncatedHover"]["shown"] == "block", "hovering a truncated legend entry must show the tooltip"
    assert seen["truncatedHover"]["text"] == "alice@example.com (long alias)", "tooltip must show the FULL name, not the truncated one"
    assert seen["truncatedLeave"] == "none", "leaving the legend entry must hide the tooltip"
    assert seen["untruncatedHover"]["shown"] == "none", "an already-full label must not pop a redundant tooltip"
    assert seen["stackedHover"]["shown"] == "block" and seen["stackedHover"]["text"] == "vllm/A-Very-Long-Model-Name-Here", (
        "mkStackByKey-built charts (conc-by-key/model, backlog-by-key) must get the same hover wiring"
    )


# ---------------------------------------------- alerts status timeline --------
def test_alerts_status_card_before_history_and_wired():
    """The 'Service status over time' card exists on /alerts, sits BEFORE the
    Alert history card, loads Chart.js, exposes the 1h/24h/1mo/1y window chips,
    and its poll is tracked in _timers (cleared on beforeunload with the rest)."""
    html = (ROOT / "web" / "alerts.html").read_text(encoding="utf-8")
    assert '<script src="/assets/chart.umd.min.js">' in html
    i_status = html.find('id="card-status"')
    i_hist = html.find('id="card-history"')
    assert i_status != -1 and i_hist != -1
    assert i_status < i_hist, "status card must render before Alert history"
    # window chips: labels 1mo/1y map to the real window tokens 30d/12mo
    for tok in ('data-w="1h"', 'data-w="24h"', 'data-w="30d"', 'data-w="12mo"'):
        assert tok in html
    # the graph is fed by the dedicated endpoint and polled on a tracked timer
    assert "/api/status-timeline?window=" in html
    assert "_timers.push(setInterval(loadStatus" in html
    # server-driven omission (no client fake): the card just draws whatever lanes arrive
    assert "no_data" in html and "buildStatusChart" in html


def test_alerts_status_card_legend_canvas_and_a11y():
    """The status card carries a self-explaining legend (up / down / no data yet),
    a canvas to mount the chart, accessible window chips (aria-pressed on the active
    one), and still escapes all dynamic strings elsewhere on the page."""
    html = (ROOT / "web" / "alerts.html").read_text(encoding="utf-8")
    assert 'id="status-chart"' in html and "<canvas" in html
    for word in (">up<", ">down<", "no data yet"):
        assert word in html, f"legend missing {word!r}"
    # exactly the four windows, active one marked pressed for assistive tech
    assert 'class="active" aria-pressed="true"' in html
    assert html.count('class="win-mini"') == 1
    # the pre-existing paintUpdated ReferenceError (missing on this non-core page)
    # is fixed by a local definition, not by pulling in aimon-core (which would clash)
    assert "function paintUpdated(" in html
    assert 'src="/assets/aimon-core.js"' not in html   # not loaded (would clash); mentioned in a comment only
    # page still sanitises + escapes (no regression from the new card)
    assert "DOMPurify.sanitize" in html and "function escapeHtml(" in html


def test_alerts_status_chart_colour_matches_height_not_reversed():
    """Regression: the status lane y-axis must NOT be reversed. reverse:true flips
    the within-lane up/down levels, so a service that's UP draws LOW while its line
    stays green — height then contradicts colour. Colour is derived from the drawn
    y-level (ctx.p0.parsed.y) precisely so height and colour can never disagree."""
    html = (ROOT / "web" / "alerts.html").read_text(encoding="utf-8")
    assert "reverse:true" not in html, "reversed y-axis inverts up/down vs green/red"
    assert "ctx.p0.parsed.y" in html, "segment colour must come from the drawn level"


def test_litellm_user_tokens_chart_fills_width_no_flicker_true_filter():
    """Three fixes to the 'volume by user over time' chart on /litellm:
      1. the SVG stretches to the card width (it has a viewBox but no width attr,
         so without an explicit CSS width it renders at its intrinsic ~920px);
      2. buildKeyUser() must NOT wipe the owner map on a budgets blip (that folded
         everyone to 'Unassigned' and made the bands flicker);
      3. the user picker is a true filter — unselected users are removed, not rolled
         into a grey 'Other' band."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    # 1. explicit width on the stacked-area SVG
    assert re.search(r"#ut-stack\{[^}]*width:100%", html), "ut-stack must be width:100%"
    # 2. owner map preserved on an empty/blip payload (early return, no unconditional reset)
    assert "function buildKeyUser(budgets){\n  const ks" in html, \
        "buildKeyUser must not reset _keyUser before checking the payload"
    # blip guard keeps the last map only when BOTH live keys and the persisted store are empty
    assert "if(!ks.length && !Object.keys(store).length) return;" in html, \
        "buildKeyUser must keep the last map on a total blip"
    # 3. no 'Other' catch-all band in utBands — unselected users are dropped
    m = re.search(r"function utBands\(\)\{.*?\n\}", html, re.S)
    assert m and "Other (" not in m.group(0), "utBands must not fold unselected users into 'Other'"


def test_litellm_user_tokens_prefers_server_owner_map():
    """The by-user chart must fold using the server's persisted owner map (d.owners)
    first, so keys resolve immediately + historical keys aren't stuck 'Unassigned';
    _keyUser (budgets/live) stays as the fallback."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert "const omap=d.owners||{}" in html
    assert "resolveOwner" in html and "usernameOf(e)" in html
    # the fold uses the resolver, not the raw budgets-only userOf
    m = re.search(r"pts\.forEach\(\(p,bi\)=>\{ labels\.forEach\(k=>\{ const u=(\w+)\(k\)", html)
    assert m and m.group(1) == "resolveOwner", "fold must use resolveOwner"


def test_litellm_user_tokens_follows_page_window():
    """The by-user chart must request its data for the selected window (+ pan cursor),
    show the window badge, and no longer advertise 'all-time' or the removed Other band."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert '/api/userreqs?window="+encodeURIComponent(WIN)' in html, "must pass the window"
    assert '&end="+Math.round(TIMEEND)' in html, "must pass the pan cursor"
    assert 'id="ut-win"' in html and 'uw.textContent=wlabel(WIN)' in html, "window badge must track WIN"
    # stale copy removed
    assert '<span class="badge">all-time</span>' not in html
    assert "fold into a grey <b>Other</b>" not in html


def test_litellm_by_user_charts_seed_owner_map_from_store():
    """buildKeyUser seeds _keyUser from the persisted store (budgets.owner_names) BEFORE the
    live budgets emails, so every by-user chart (userOf) is warm + covers historical keys, and
    a blip keeps the last map only when BOTH live keys and the store are empty."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert "const store = (budgets && budgets.owner_names)" in html
    i_store = html.find("for(const lbl in store){ const u = usernameOf(store[lbl])")
    i_live = html.find("ks.forEach(k=>{ if(k && k.key){ const u = usernameOf(k.email)")
    assert i_store != -1 and i_live != -1 and i_store < i_live, "store must seed before live"
    assert "if(!ks.length && !Object.keys(store).length) return;" in html


def test_litellm_cards_show_loading_overlay_on_first_paint():
    """Slow graphs must read as 'Loading…' on first paint, not empty 'no data'. Every chart
    card gets a .card-loading overlay at startup; a data-backed card keeps it until it HAS
    data (_cardTry / _cardHasData), bounded so a genuinely-empty window doesn't spin forever;
    cards where empty is valid+fast (KPIs, failures, anomalies) reveal at once (_cardShow)."""
    html = (ROOT / "web" / "litellm.html").read_text(encoding="utf-8")
    assert ".card-loading{" in html, "overlay style missing"
    assert 'ov.className="card-loading"' in html, "overlay not injected at startup"
    assert "function _cardHasData(" in html and "function _cardTry(" in html \
        and "function _cardShow(" in html
    assert "_EMPTY_MAX" in html, "bounded fallback missing (would spin forever)"
    assert "Chart.getChart" in html, "canvas data-check missing"
    # slow LiteLLM /spend-backed cards use _cardTry (stay until data); fast/local cards use _cardShow
    for cid in ('"card-models"', '"card-usertokens"', '"card-keydelta"'):
        assert f"_cardTry({cid}" in html or f',{cid}' in html, f"{cid} not held for data"
    assert '_cardShow("card-kpi"' in html and '_cardShow("card-anomalies")' in html
    # fast /api/data cards reveal right away (regression: they used to hold + show blank)
    assert '_cardShow("card-kpi","card-failures","card-keys","card-userkeys")' in html
