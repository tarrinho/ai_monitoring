// aimon-core.js — shared helpers used by every dashboard page (review D-3).
//
// Self-hosted so it stays within the strict CSP (script-src 'self'; no CDN). It is a CLASSIC
// script, so it shares the page's global lexical scope: its functions read the page globals
// (AUTH, TIMEEND) that each page's inline script declares. Those functions are only CALLED at
// runtime (from a page's loaders, after init), so the globals are always initialised by then.
//
// Extracted here so a change like the pan/zoom `end=` append can't drift between the ~9
// per-page copies it used to live in (copy-paste drift caused real bugs — see the review).

// Fetch a JSON API path with the page's auth token, appending the pan/zoom cursor (`end=`) when
// the page HAS one. WIN pages declare `let TIMEEND`; the Spend page has no pan cursor, so the
// `typeof` guard skips the append there instead of throwing a ReferenceError (which is why the
// Spend page used to carry a hand-trimmed copy of this function).
async function api(path){
  if(typeof TIMEEND!=="undefined" && TIMEEND && path.indexOf("window=")>=0)
    path += (path.includes("?")?"&":"?")+"end="+TIMEEND.toFixed(0);
  try{
    const sep=path.includes("?")?"&":"?";
    const url=path+(AUTH?(sep+"token="+encodeURIComponent(AUTH)):"");
    const r=await fetch(url,{headers:AUTH?{Authorization:"Bearer "+AUTH}:{}});
    if(!r.ok){ document.getElementById("updated").textContent="auth/error "+r.status; return null; }
    return await r.json();
  }catch(e){ document.getElementById("updated").textContent="disconnected"; return null; }
}

// ---- Per-page time window + pan/zoom cursor (review D-3): identical across every WIN
// page, so extracted here to stop copy-paste drift. Functions read/write the page
// globals WIN / TIMEEND / WSECS (shared classic-script scope) and call the page's
// updateRangeUI()/rangedReload() only at runtime (from event handlers), by which time
// each page's inline script has defined them. Pages without a pan cursor (spend,
// settings) load this too; the drag listeners early-return there (no timestamped chart).

function wsecs(w){ if(typeof w==="string"&&w.indexOf("custom:")===0){var cs=parseInt(w.slice(7),10); if(cs>0) return cs;} return w==="month"?(Date.now()-Date.UTC(new Date().getUTCFullYear(),new Date().getUTCMonth(),1))/1000:(WSECS[w]||3600);}

function _winKey(){ return "aimon-win:"+location.pathname; }

function _winCustom(w){ // STRICT "custom:<digits>" only. A loose check let a poisoned localStorage value like "custom:3600&x=1" pass, then flow unencoded into the export URL + api() query string (param injection). Anchored regex closes that.
  return typeof w==="string" && /^custom:[0-9]+$/.test(w) && parseInt(w.slice(7),10)>0; }

function _winSave(w, end){ try{ localStorage.setItem(_winKey(), JSON.stringify({w:w, end:(end||null)})); }catch(e){} }

function _winRestore(sel, def, labelId){
  var s=null; try{ s=JSON.parse(localStorage.getItem(_winKey())||"null"); }catch(e){}
  var w=s&&s.w;
  if(_winCustom(w)){
    TIMEEND=Number(s&&s.end)||null;           // absolute custom range persists across refresh
    setTimeout(function(){ _winMark(true); },0);   // mark it: a frozen window isn't a dead dashboard
    document.querySelectorAll(sel+' button[data-w]').forEach(function(x){
      x.classList.remove("active"); x.setAttribute("aria-pressed","false"); });
    if(labelId){ var lc=document.getElementById(labelId); if(lc) lc.textContent="custom"; }
    return w;
  }
  // Only a safe-charset token may reach the querySelector interpolation below: a malformed restored value would otherwise throw a SyntaxError and crash page init (named windows are alphanumeric: 1h/24h/30d/12mo/month).
  if(!(w && /^[a-z0-9]+$/i.test(w) && document.querySelector(sel+' button[data-w="'+w+'"]'))) w=def;
  document.querySelectorAll(sel+' button[data-w]').forEach(function(x){
    var on=x.dataset.w===w; x.classList.toggle("active",on); x.setAttribute("aria-pressed", on?"true":"false"); });
  if(labelId){ var l=document.getElementById(labelId); if(l) l.textContent=w; }
  return w;
}

function _winMark(on){
  var l=document.getElementById("win-label"); if(!l) return;
  l.classList.toggle("custom-win", !!on);
  l.title = on ? "Custom range from a chart selection — click Live to resume live data" : "";
}

function wlabel(w){ return (typeof w==="string" && w.indexOf("custom:")===0) ? "custom" : w; }

// Shared freshness indicator for the #updated span. `lastOkMs` = Date.now() at the last
// SUCCESSFUL data update; call this every tick (success or failure) so the age keeps growing
// while a poll is failing — a frozen/erroring page then visibly goes green(<15s)→amber(<60s)→
// red instead of showing a static timestamp that looks fresh forever. The age is a pure
// client-clock delta (Date.now()-lastOkMs), so it's immune to client/server clock skew.
function paintUpdated(elId, lastOkMs){
  var el=document.getElementById(elId); if(!el||!lastOkMs) return;
  var age=Math.max(0,(Date.now()-lastOkMs)/1000);
  el.textContent="updated "+new Date(lastOkMs).toLocaleTimeString()+(age>=15?" ("+Math.round(age)+"s ago)":"");
  el.style.color = age>=60?"var(--bad)":age>=15?"var(--warn)":"var(--muted)";
}

function stampTs(ch, pts){ try{ if(ch) ch.$ts=(pts||[]).map(function(p){ return p && p.t; }); }catch(e){} }

// Make a click-to-toggle control keyboard + assistive-tech accessible: a plain <div> with a
// click handler is mouse-only (not focusable, no Enter/Space). This sets role=button + tabindex
// and activates onToggle on click AND Enter/Space, so the collapsible section headers work
// without a mouse. Keep aria-expanded in sync in the caller's apply() (see index.html).
function a11yToggle(el, onToggle){
  el.setAttribute("role","button");
  el.setAttribute("tabindex","0");
  function fire(ev){
    if(ev.type==="keydown"){
      if(ev.key!=="Enter"&&ev.key!==" "&&ev.key!=="Spacebar") return;
      ev.preventDefault();
    }
    onToggle();
  }
  el.addEventListener("click", fire);
  el.addEventListener("keydown", fire);
}

// ---- drag-to-zoom: drag across ANY chart to set a custom time window (Kibana-style) ----
(function(){
  var dg=null;
  function chartOf(cv){ return (window.Chart && Chart.getChart) ? Chart.getChart(cv) : null; }
  function place(x){
    if(!dg||!dg.ov) return; var a=dg.ch.chartArea, r=dg.cv.getBoundingClientRect();
    var lo=Math.max(a.left, Math.min(dg.x0,x)-r.left), hi=Math.min(a.right, Math.max(dg.x0,x)-r.left);
    dg.ov.style.left=lo+"px"; dg.ov.style.width=Math.max(0,hi-lo)+"px";
    dg.ov.style.top=a.top+"px"; dg.ov.style.height=(a.bottom-a.top)+"px";
  }
  function abort(){ if(dg&&dg.ov&&dg.ov.parentNode) dg.ov.parentNode.removeChild(dg.ov); dg=null; }
  document.addEventListener("pointerdown",function(e){
    if(e.button) return;
    var wrap=e.target.closest && e.target.closest(".chart-wrap"); if(!wrap) return;
    var cv=wrap.querySelector("canvas"); if(!cv) return;
    var ch=chartOf(cv); if(!ch||!ch.chartArea) return;
    // Time-series charts only. A by-key BAR chart's x-axis is key names, not time — a drag
    // there would map pixels onto a time range that means nothing. $ts is set by stampTs(),
    // so only charts plotted against real timestamps are draggable.
    if(!ch.$ts || ch.$ts.length<2) return;
    // Start ONLY inside the plot area: Chart.js paints the legend on the same canvas, so
    // grabbing the whole wrap would swallow the click that toggles a series on/off.
    var a=ch.chartArea, r=cv.getBoundingClientRect(), x=e.clientX-r.left, y=e.clientY-r.top;
    if(x<a.left||x>a.right||y<a.top||y>a.bottom) return;
    dg={wrap:wrap,cv:cv,ch:ch,x0:e.clientX,ov:null,moved:false};
  });
  document.addEventListener("pointermove",function(e){
    if(!dg) return;
    if(!dg.moved){
      if(Math.abs(e.clientX-dg.x0)<5) return;      // still a click, not a drag
      dg.moved=true;
      dg.ov=document.createElement("div"); dg.ov.className="drag-sel"; dg.wrap.appendChild(dg.ov);
    }
    e.preventDefault();                            // suppress text selection ONLY while dragging
    place(e.clientX);
  });
  document.addEventListener("pointercancel",abort);   // pointer lost (gesture/scroll/OS) → clean up
  window.addEventListener("blur",abort);              // released outside the window → no stuck overlay
  document.addEventListener("pointerup",function(e){
    if(!dg) return; var d=dg; abort();
    if(!d.moved) return;                           // a click: let the chart handle it
    var a=d.ch.chartArea, r=d.cv.getBoundingClientRect(), w=a.right-a.left; if(w<=0) return;
    var px1=Math.min(d.x0,e.clientX)-r.left, px2=Math.max(d.x0,e.clientX)-r.left;
    var t1=null, t2=null, ts=d.ch.$ts, xs=d.ch.scales&&d.ch.scales.x;
    if(ts&&ts.length>1&&xs&&xs.getValueForPixel){
      // exact: pixel -> point index -> that point's real timestamp (handles data gaps)
      var i1=Math.round(xs.getValueForPixel(px1)), i2=Math.round(xs.getValueForPixel(px2));
      i1=Math.max(0,Math.min(ts.length-1,i1)); i2=Math.max(0,Math.min(ts.length-1,i2));
      if(isFinite(ts[i1])&&isFinite(ts[i2])){ t1=ts[i1]; t2=ts[i2]; }
    }
    if(t1===null){                                 // fallback: fraction of the requested window
      var f1=Math.max(0,Math.min(1,(px1-a.left)/w)), f2=Math.max(0,Math.min(1,(px2-a.left)/w));
      var end=TIMEEND||Date.now()/1000, s=end-wsecs(WIN), span=end-s;
      t1=s+f1*span; t2=s+f2*span;
    }
    if(!(t2-t1>=30)) return;                       // ignore < 30s selections
    WIN="custom:"+Math.round(t2-t1); TIMEEND=t2; _winSave(WIN, TIMEEND);
    document.querySelectorAll("#windows button[data-w]").forEach(function(x){x.classList.remove("active");x.setAttribute("aria-pressed","false");});
    document.querySelectorAll('#win-label,[id$="-win"]').forEach(function(el){ el.textContent="custom"; });
    _winMark(true);
    if(typeof updateRangeUI==="function") updateRangeUI();
    rangedReload();
  });
})();

// ---- shared label truncation + hover "full name" tooltip -------------------------------
// Long key hashes / model / user names get shortened for axis ticks & legends across the
// dashboard. One truncation rule (was 3 near-identical copies across litellm.html) and one
// hover-tooltip implementation, so every chart on every page behaves the same instead of
// hand-rolling it per page.
function _shortLbl(s, head, tail, threshold){
  s = String(s==null ? "?" : s);
  head = head||8; tail = tail||4; threshold = threshold||18;
  return s.length>threshold ? s.slice(0,head)+"…"+s.slice(-tail) : s;
}

// One shared floating bubble per page, reused by every chart — like a native `title`
// tooltip, but works for canvas-drawn Chart.js legend items, which have no real DOM node
// for the browser's own hover tooltip to attach to.
let _lblTipEl = null;
function _lblTip(){
  if(_lblTipEl) return _lblTipEl;
  _lblTipEl = document.createElement("div");
  _lblTipEl.id = "lbl-tip";
  _lblTipEl.setAttribute("role","tooltip");
  Object.assign(_lblTipEl.style, {
    position:"fixed", zIndex:"60", display:"none", pointerEvents:"none",
    background:"var(--panel2,#161b22)", color:"var(--fg,#e6edf3)",
    border:"1px solid var(--border,#30363d)", borderRadius:"5px",
    padding:"4px 8px", fontSize:"11px", fontFamily:"inherit", maxWidth:"360px",
    boxShadow:"0 4px 14px rgba(0,0,0,.35)", whiteSpace:"nowrap", overflow:"hidden",
    textOverflow:"ellipsis"
  });
  document.body.appendChild(_lblTipEl);
  return _lblTipEl;
}
function showLblTip(x, y, text){
  const el=_lblTip(); el.textContent=text; el.style.display="block";
  const vw=window.innerWidth||1200, vh=window.innerHeight||800;
  const w=Math.min(el.offsetWidth||200,360);
  el.style.left=Math.max(4,Math.min(x+12,vw-w-4))+"px";
  el.style.top=Math.max(4,Math.min(y+14,vh-28))+"px";
}
function hideLblTip(){ if(_lblTipEl) _lblTipEl.style.display="none"; }

// Wire hover-to-reveal-full-name onto a Chart.js chart's canvas-drawn legend. `getFull(item)`
// returns the untruncated string for a given Chart.js legend item (item.text is what's
// currently shown). If it differs from item.text, hovering the legend entry shows the full
// name in the floating tooltip; leaving it hides the tooltip. No-op when nothing is
// truncated (getFull returns the same string, or null/undefined).
function wireLegendFullName(chart, getFull){
  // Mutate the RAW config (`chart.config.options`), NOT the resolved `chart.options` proxy.
  // On Chart.js v4.4, assigning into the reactive `chart.options.plugins.legend.*` proxy
  // recurses infinitely (Object.set ↔ Object.set) and hard-hangs the page at load — the
  // resolved options read through to config, so setting onHover/onLeave on config is picked
  // up for the legend hover events all the same, without touching the proxy.
  const o = chart && chart.config && chart.config.options;
  if(!o) return;
  o.plugins = o.plugins || {};
  o.plugins.legend = o.plugins.legend || {};
  const prevHover = o.plugins.legend.onHover;
  const prevLeave = o.plugins.legend.onLeave;
  o.plugins.legend.onHover = function(evt, item, legend){
    if(prevHover) prevHover(evt, item, legend);
    const full = getFull(item);
    const shown = item && item.text;
    if(full && shown && String(full)!==String(shown) && evt && evt.native){
      showLblTip(evt.native.clientX, evt.native.clientY, String(full));
    } else hideLblTip();
  };
  o.plugins.legend.onLeave = function(evt, item, legend){
    if(prevLeave) prevLeave(evt, item, legend);
    hideLblTip();
  };
}
