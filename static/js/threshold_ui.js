/* =============================================================================
   Net-monit V11.3 -- shared threshold table (Settings > Thresholds, Settings notify modal, Devices notify modal)
   -----------------------------------------------------------------------------
   Renders from GET /api/threshold-meta (monitor/threshold_meta.py is the single source of truth), so a
   website shows website metrics (response time, SSL days left, SSL handshake, DNS, TCP connect) and a
   device shows device metrics -- each with its unit, which direction is bad, the allowed minimum/maximum
   and the recommended warning/critical values.

   Element ids stay compatible with the old screens: pass the same id prefixes ({en,w,c,wait}).
   Pure functions take the catalogue as an argument so they can be unit-tested in Node.

   V11.2: the table is compact. Each metric shows only its name, unit, Enabled, Warning, Critical (and Wait).
   Everything else (direction, meaning, allowed minimum/maximum, recommended values, what a healthy value looks
   like) lives in a small "!" button next to the metric name: hover (or keyboard-focus) it to read the details
   while the pointer stays on it or on the details box; click it to PIN the box open with an X to close it
   (Esc also closes). One floating box is shared by every table, so it is never clipped by a scrolling table or
   a modal.
   ============================================================================= */
const ThrUI = (function () {
  let _meta = null, _promise = null;

  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function load() {
    if (_meta) return Promise.resolve(_meta);
    if (_promise) return _promise;
    const hdr = (typeof getSession === "function") ? { "X-Session-Token": getSession() } : {};
    _promise = fetch("/api/threshold-meta", { headers: hdr })
      .then(r => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(j => { _meta = j; return j; })
      .catch(e => { _promise = null; throw e; });
    return _promise;
  }
  function get() { return _meta; }
  function setMeta(m) { _meta = m; _promise = null; }

  function metricsFor(meta, method) {
    return (meta.methods && meta.methods[method]) ? meta.methods[method].slice() : meta.device_metrics.slice();
  }
  function defaultsFor(metric) {            // {warning, critical} or {} when the catalogue is not loaded yet
    const m = _meta && _meta.metrics[metric];
    return m ? { warning: m.warning, critical: m.critical } : {};
  }
  function dirText(m) {
    return m.lower_is_worse ? "\u25BC alerts when the value falls BELOW the threshold"
                            : "\u25B2 alerts when the value rises ABOVE the threshold";
  }
  function rangeText(m) { return m.min + " \u2013 " + m.max + " " + m.unit; }
  function recText(m) { return "Warning " + m.warning + " \u00B7 Critical " + m.critical + " " + m.unit; }

  /* The text shown in the "!" box for one metric (pure: unit-tested). */
  function infoHTML(m) {
    return '<div class="thr-pop-h"><strong>' + esc(m.label) + ' <span class="thr-pop-unit">(' + esc(m.unit) + ')</span></strong>' +
      '<button type="button" class="thr-pop-x" aria-label="Close details" title="Close">\u00D7</button></div>' +
      '<div class="thr-pop-dir' + (m.lower_is_worse ? ' low' : '') + '">' + esc(dirText(m)) + '</div>' +
      '<p class="thr-pop-hint">' + esc(m.hint) + '</p>' +
      '<dl class="thr-pop-dl">' +
        '<dt>Allowed range</dt><dd>' + esc(rangeText(m)) + ' <span class="thr-pop-sub">(minimum \u2013 maximum)</span></dd>' +
        '<dt>Recommended</dt><dd>' + esc(recText(m)) + '</dd>' +
        '<dt>Healthy</dt><dd>' + esc(m.good) + '</dd>' +
      '</dl>';
  }
  function infoButton(k, m) {
    return '<button type="button" class="thr-i" data-thr="' + esc(k) + '" aria-label="Details about ' + esc(m.label) +
      '" aria-haspopup="dialog">!</button>';
  }

  /* ids = {en, w, c, wait} id prefixes; opts = {wait: bool, waitPlaceholder: number|string} */
  function tableHTML(meta, metrics, saved, ids, opts) {
    opts = opts || {};
    saved = saved || {};
    const showWait = !!opts.wait;
    const rows = metrics.map(k => {
      const m = meta.metrics[k]; if (!m) return "";
      const s = saved[k] || {};
      const inh = (opts.inherit && opts.inherit[k]) || m;       // placeholder = the value this row falls back to
      const num = (id, val, ph) =>
        '<input type="number" id="' + esc(id) + '" step="any" min="' + m.min + '" max="' + m.max + '" style="width:76px" ' +
        'value="' + (val != null ? esc(val) : "") + '" placeholder="' + esc(ph) + '">';
      return '<tr>' +
        '<td style="min-width:200px"><span style="font-weight:600;font-size:13px">' + esc(m.label) +
          ' <span style="color:var(--text-muted);font-weight:400">(' + esc(m.unit) + ')</span></span> ' + infoButton(k, m) +
          (m.lower_is_worse ? ' <span class="thr-dir" title="Alerts when the value falls below the threshold">\u25BC alerts when below</span>' : '') + '</td>' +
        '<td style="text-align:center"><input type="checkbox" id="' + esc(ids.en + k) + '"' + (s.enabled !== false ? " checked" : "") + '></td>' +
        '<td>' + num(ids.w + k, s.warning, inh.warning) + '</td>' +
        '<td>' + num(ids.c + k, s.critical, inh.critical) + '</td>' +
        (showWait ? '<td><input type="number" id="' + esc(ids.wait + k) + '" min="0" style="width:72px" value="' +
          (s.wait_sec != null ? esc(s.wait_sec) : "") + '" placeholder="' + esc(opts.waitPlaceholder != null ? opts.waitPlaceholder : "") + '"></td>' : "") +
        (opts.sources ? '<td class="thr-src">' + esc(opts.sources[k] || "built-in") + '</td>' : "") +
        '</tr>';
    }).join("");
    return '<table class="data-table thr-table" style="margin:0"><thead><tr><th>Metric</th><th>Enabled</th><th>Warning</th><th>Critical</th>' +
      (showWait ? '<th title="Seconds this metric must stay bad before the first alert fires in &quot;Wait to confirm&quot; mode. Blank = use this device\'s Level 1 time.">Wait (sec)</th>' : "") +
      (opts.sources ? '<th>Comes from</th>' : "") +
      '</tr></thead><tbody>' + rows + '</tbody></table>';
  }

  /* Read the table back. Returns {thresholds, errors}. Mirrors the server-side validation so the person
     gets the message before the request is sent. */
  function collect(meta, metrics, ids, opts, getEl) {
    opts = opts || {};
    getEl = getEl || (id => document.getElementById(id));
    const out = {}, errors = [];
    metrics.forEach(k => {
      const m = meta.metrics[k]; if (!m) return;
      const w = getEl(ids.w + k), c = getEl(ids.c + k), en = getEl(ids.en + k);
      if (!w) return;
      const row = { enabled: en ? !!en.checked : true };
      const vals = {};
      [["warning", w], ["critical", c]].forEach(([fld, el]) => {
        if (!el || el.value === "" || el.value == null) return;
        const f = parseFloat(el.value);
        if (!isFinite(f)) { errors.push(m.label + ": " + fld + " must be a number."); return; }
        if (f < m.min || f > m.max) {
          errors.push(m.label + ": " + fld + " " + f + " is outside the allowed range " + m.min + " to " + m.max + " " + m.unit + ".");
          return;
        }
        row[fld] = f; vals[fld] = f;
      });
      if (vals.warning != null && vals.critical != null) {
        if (m.lower_is_worse && vals.warning < vals.critical)
          errors.push(m.label + ": warning (" + vals.warning + ") must be higher than critical (" + vals.critical +
                      ") because this metric alerts when the value falls BELOW the threshold.");
        if (!m.lower_is_worse && vals.warning > vals.critical)
          errors.push(m.label + ": warning (" + vals.warning + ") must be lower than critical (" + vals.critical + ").");
      }
      if (opts.wait) {
        const wt = getEl(ids.wait + k);
        if (wt && wt.value !== "") row.wait_sec = parseInt(wt.value) || 0;
      }
      out[k] = row;
    });
    return { thresholds: out, errors };
  }

  /* Drop rows that change nothing (enabled, no values, no wait) so a blank row means "inherit", not "set here". */
  function compact(thresholds) {
    const out = {};
    Object.keys(thresholds || {}).forEach(k => {
      const r = thresholds[k] || {};
      if (r.warning != null || r.critical != null || r.wait_sec != null || r.enabled === false) out[k] = r;
    });
    return out;
  }

  function fillRecommended(meta, metrics, ids, getEl) {
    getEl = getEl || (id => document.getElementById(id));
    metrics.forEach(k => {
      const m = meta.metrics[k]; if (!m) return;
      const w = getEl(ids.w + k), c = getEl(ids.c + k), en = getEl(ids.en + k);
      if (w) w.value = m.warning;
      if (c) c.value = m.critical;
      if (en) en.checked = true;
    });
  }

  /* Compact chips per device for the "active thresholds" table:
     [Response time 1000/5000 ms] [SSL certificate expires in 30/7 days] ... (bold = this device overrides it). */
  function summaryHTML(meta, method, deviceSaved, globalSaved) {
    deviceSaved = deviceSaved || {}; globalSaved = globalSaved || {};
    return '<div class="thr-chips">' + metricsFor(meta, method).map(k => {
      const m = meta.metrics[k]; if (!m) return "";
      const d = deviceSaved[k] || {}, g = globalSaved[k] || {};
      const off = d.enabled === false || (d.enabled == null && g.enabled === false);
      const pick = (fld) => d[fld] != null ? [d[fld], true] : (g[fld] != null ? [g[fld], false] : [m[fld], false]);
      const [w, wo] = pick("warning"), [c, co] = pick("critical");
      const fmt = (v, o) => o ? "<strong>" + esc(v) + "</strong>" : '<span style="color:var(--text-muted)">' + esc(v) + "</span>";
      return '<span class="thr-chip' + (off ? " off" : "") + (wo || co ? " ovr" : "") + '">' +
        '<span class="thr-chip-n">' + esc(m.label) + "</span> " + fmt(w, wo) + "/" + fmt(c, co) +
        ' <span class="thr-chip-u">' + esc(m.unit) + "</span></span>";
    }).join("") + "</div>";
  }

  /* ---- V11.2: "Apply wait & cooldown to all devices / only devices / only sites" ------------------------
     Reads {prefix}-trigger-mode, {prefix}-wait-sec, {prefix}-notify-mode, {prefix}-cooldown-sec (prefix = "esc-g"
     on the Escalation tab, "snm" in the Settings notify window, "nm" in the Devices notify window) and posts them
     to POST /api/settings/notify-timing/apply. Only the timing fields change on the server. */
  const TIMING_SCOPE = { all: "ALL devices and sites", devices: "ALL devices (websites excluded)", sites: "ALL sites (websites only)" };
  function timingPayload(scope, prefix, getEl) {
    getEl = getEl || (id => document.getElementById(id));
    const val = (n) => { const e = getEl(prefix + "-" + n); return e ? e.value : undefined; };
    const tgt = (scope && typeof scope === "object") ? (scope.body || {}) : { scope: scope };   // V11.3 patch 06: target object or legacy scope string
    return Object.assign({}, tgt, {
             alert_trigger_mode: val("trigger-mode") || "sustained",
             wait_sec: parseInt(val("wait-sec")) || 60,
             alert_notify_mode: val("notify-mode") || "immediate",
             notify_cooldown_sec: parseInt(val("cooldown-sec")) || 300 });
  }
  function timingConfirmText(p, tgt) {
    const wait = p.alert_trigger_mode === "sustained" ? ("Wait to confirm: alert only if the problem lasts " + p.wait_sec + " seconds")
                                                      : "Immediate: alert the moment a problem is detected";
    const rep  = p.alert_notify_mode === "cooldown" ? ("Repeat alerts: at least " + p.notify_cooldown_sec + " seconds apart")
                                                    : "Repeat alerts: immediate (no extra gap)";
    return "Apply these settings to " + (tgt ? (tgt.label + " (" + tgt.count + ")") : (TIMING_SCOPE[p.scope] || p.scope)) + "?\n\n\u2022 " + wait + "\n\u2022 " + rep +
      "\n\nEmails, SMS/call numbers, escalation levels and thresholds are not changed. " +
      (p.alert_trigger_mode === "sustained" ? "Per-metric wait overrides are removed so this wait time really applies." : "");
  }
  async function applyTiming(scope, prefix, o) {
    o = o || {};
    const p = timingPayload(scope, prefix, o.getEl);
    const ask = o.confirmFn || ((typeof confirm === "function") ? confirm : () => true);
    if (!ask(timingConfirmText(p, (scope && typeof scope === "object") ? scope : null))) return { cancelled: true };
    const hdr = (typeof authHeaders === "function") ? authHeaders()
              : Object.assign({ "Content-Type": "application/json" }, (typeof getSession === "function") ? { "X-Session-Token": getSession() } : {});
    const f = o.fetchFn || fetch;
    const r = await f("/api/settings/notify-timing/apply", { method: "POST", headers: hdr, body: JSON.stringify(p) });
    let j = {}; try { j = await r.json(); } catch (_) {}
    if (!r.ok || !j.ok) return { ok: false, message: (j && j.error) || ("Apply failed (" + r.status + ")") };
    const what = scope === "sites" ? "site" : (scope === "devices" ? "device" : "monitor");   // object targets: "monitor"
    return { ok: true, count: j.count, message: "Applied to " + j.count + " " + what + (j.count === 1 ? "" : "s") + " \u2713" };
  }


  /* ---- V11.3 patch 06: context-aware "apply to ..." targets --------------------------------------------
     For the device being edited it offers: this device / every device of the same TYPE / every monitor with the
     same CHECK METHOD / all devices (or all sites) / the monitors in the page's CURRENT SEARCH OR FILTER. */
  let _ctxCache = null;
  async function context(deviceId, o) {
    o = o || {};
    const f = o.fetchFn || fetch, hdr = (typeof authHeaders === "function") ? authHeaders() : {};
    if (!_ctxCache || (Date.now() - _ctxCache.t) > 15000) {
      const [a, b] = await Promise.all([f("/api/devices", { headers: hdr }).then(r => r.json()), f("/api/monitor-facets", { headers: hdr }).then(r => r.json())]);
      _ctxCache = { t: Date.now(), devices: a, facets: b };
    }
    const d = (_ctxCache.devices || []).find(x => x.id === deviceId) || { id: deviceId };
    const methodOf = {}; (_ctxCache.devices || []).forEach(x => { methodOf[x.id] = x.method || ""; });
    return { dev: { id: d.id, name: d.name || d.id, type: d.type || "", method: d.method || "ping", isSite: (d.method || "") === "url" }, facets: _ctxCache.facets || {}, methodOf: methodOf };
  }
  function resetContext() { _ctxCache = null; }
  function targets(dev, facets, filterIds, o) {
    o = o || {};
    const f = facets || {}, cnt = (a, id) => ((a || []).find(x => x.id === id) || {}).count || 0,
          lab = (a, id) => ((a || []).find(x => x.id === id) || {}).label || id;
    const total = (f.methods || []).reduce((n, x) => n + (x.count || 0), 0), sites = cnt(f.methods, "url"), devs = total - sites;
    const out = [{ key: "this", label: dev.isSite ? "This site only" : "This device only", count: 1, body: { ids: [dev.id] } }];
    if (!dev.isSite) {
      const tn = cnt(f.types, dev.type), mn = cnt(f.methods, dev.method);
      if (tn > 1) out.push({ key: "type", label: "All " + lab(f.types, dev.type) + " devices", count: tn, body: { kind: "type", key: dev.type } });
      if (mn > 1) out.push({ key: "method", label: "All " + lab(f.methods, dev.method) + " monitors", count: mn, body: { kind: "method", key: dev.method } });
      out.push({ key: "devices", label: "All devices", count: devs, body: { scope: "devices" } });
    } else {
      out.push({ key: "sites", label: "All sites", count: sites, body: { scope: "sites" } });
    }
    // a filter only counts monitors of the same kind (websites never mix with devices: their metrics differ)
    if (filterIds && o.methods) filterIds = filterIds.filter(id => ((o.methods[id] || "") === "url") === !!dev.isSite);
    if (filterIds && filterIds.length > 1) out.push({ key: "filter", label: "Current search / filter", count: filterIds.length, body: { ids: filterIds } });
    return out;
  }
  function barHTML(label, items, fnName) {
    return '<span class="lbl">' + esc(label) + '</span>' + items.map(t =>
      '<button type="button" class="btn secondary small" title="' + esc(t.label + ": " + t.count + (t.count === 1 ? " monitor" : " monitors")) + '" onclick="' + fnName + "('" + t.key + "')\">" +
      esc(t.label) + ' <span class="cnt">' + t.count + "</span></button>").join("");
  }
  function thrConfirmText(t, n) {
    const rows = n + " threshold row" + (n === 1 ? "" : "s");
    return "Write these " + rows + " to " + t.label.toLowerCase().replace(/^all /, "all ") + " (" + t.count + ")?\n\n" +
           "Each of those monitors gets these as its OWN values, so you will see them in every one of their windows. " +
           "A metric that does not apply to a monitor's check method is skipped for that monitor. Blank rows and everything else are left unchanged.";
  }
  async function applyThr(t, thresholds, o) {
    o = o || {};
    const th = compact(thresholds || {}), n = Object.keys(th).length;
    if (!n) return { ok: false, message: "Fill in at least one threshold row first (blank rows are not applied)." };
    const ask = o.confirmFn || ((typeof confirm === "function") ? confirm : () => true);
    if (t.key !== "this" && !ask(thrConfirmText(t, n))) return { cancelled: true };
    // V11.3 patch 08: ONE rule for every target. The values are written to each chosen monitor as its own value (this
    // device, same type, same method, all devices/sites, current filter). Before, "same type/method/all" saved a hidden
    // default and removed the devices' own values, so the other devices' windows still showed the old grey numbers
    // and it looked as if nothing had been applied.
    const hdr = (typeof authHeaders === "function") ? authHeaders() : { "Content-Type": "application/json" };
    const r = await (o.fetchFn || fetch)("/api/devices/thresholds/apply", { method: "POST", headers: hdr, body: JSON.stringify(Object.assign({}, t.body, { thresholds: th })) });
    let j = {}; try { j = await r.json(); } catch (_) {}
    if (!r.ok || !j.ok) return { ok: false, message: (j && j.error) || ("Apply failed (" + r.status + ")") };
    resetContext();
    const c = (j.count != null ? j.count : t.count);
    return { ok: true, count: c, skipped: j.skipped || 0, message: "Thresholds written to " + c + " monitor" + (c === 1 ? "" : "s") + (j.skipped ? " (" + j.skipped + " skipped: metric not measured by their check method)" : "") + " \u2713" };
  }
  /* what each box falls back to when it is left blank, and where that number comes from (data = /api/devices/<id>/thresholds) */
  function inheritInfo(data) {
    const inherit = {}, sources = {};
    ((data && data.metrics) || []).forEach(m => {
      const has = m.override && (m.override.warning != null || m.override.critical != null || m.override.enabled != null);
      inherit[m.key] = (m.inherited && (m.inherited.warning != null || m.inherited.critical != null)) ? m.inherited : m.effective;
      sources[m.key] = has ? "this device" : ((m.inherited && m.inherited.source) || m.source || "built-in");
    });
    return { inherit, sources };
  }

  /* ---- the floating "!" box (browser only) --------------------------------------------------------- */
  let _pop = null, _cur = null, _pinned = false, _hideT = null, _bound = false;

  function _ensurePop() {
    if (_pop && _pop.isConnected) return _pop;
    _pop = document.createElement("div");
    _pop.id = "thr-pop"; _pop.className = "thr-pop"; _pop.setAttribute("role", "dialog");
    _pop.style.display = "none";
    _pop.addEventListener("mouseenter", () => { clearTimeout(_hideT); });
    _pop.addEventListener("mouseleave", () => { if (!_pinned) _scheduleHide(); });
    _pop.addEventListener("click", (e) => { if (e.target.closest && e.target.closest(".thr-pop-x")) closeInfo(); });
    document.body.appendChild(_pop);
    return _pop;
  }
  function _place() {
    if (!_pop || !_cur) return;
    const r = _cur.getBoundingClientRect(), vw = window.innerWidth, vh = window.innerHeight;
    _pop.style.left = "0px"; _pop.style.top = "0px";
    const pw = _pop.offsetWidth, ph = _pop.offsetHeight, gap = 8;
    let left = r.right + gap;
    if (left + pw > vw - 8) left = Math.max(8, r.left - gap - pw);          // no room on the right: open to the left
    if (left + pw > vw - 8) left = Math.max(8, vw - 8 - pw);               // narrow screen: clamp
    let top = r.top - 6;
    if (top + ph > vh - 8) top = Math.max(8, vh - 8 - ph);
    _pop.style.left = Math.round(left) + "px"; _pop.style.top = Math.round(top) + "px";
  }
  function showInfo(btn, pin) {
    const k = btn.getAttribute("data-thr"), m = _meta && _meta.metrics[k];
    if (!m) return;
    clearTimeout(_hideT);
    if (_cur && _cur !== btn) _cur.setAttribute("aria-expanded", "false");
    _ensurePop(); _cur = btn; _pinned = !!pin;
    _pop.innerHTML = infoHTML(m);
    _pop.classList.toggle("pinned", _pinned);
    _pop.style.display = "block";
    btn.setAttribute("aria-expanded", "true");
    _place();
  }
  function closeInfo() {
    clearTimeout(_hideT);
    if (_cur) _cur.setAttribute("aria-expanded", "false");
    if (_pop) { _pop.style.display = "none"; _pop.classList.remove("pinned"); }
    _cur = null; _pinned = false;
  }
  function _scheduleHide() { clearTimeout(_hideT); _hideT = setTimeout(() => { if (!_pinned) closeInfo(); }, 220); }
  function infoState() { return { open: !!(_pop && _pop.style.display !== "none"), pinned: _pinned, metric: _cur ? _cur.getAttribute("data-thr") : null }; }

  function bindInfo() {
    if (_bound || typeof document === "undefined" || typeof document.addEventListener !== "function") return;
    _bound = true;
    const btnOf = (t) => (t && t.closest) ? t.closest(".thr-i") : null;
    document.addEventListener("mouseover", (e) => { const b = btnOf(e.target); if (b && !_pinned) showInfo(b, false); });
    document.addEventListener("mouseout",  (e) => {
      const b = btnOf(e.target); if (!b || _pinned) return;
      const to = e.relatedTarget;
      if (to && _pop && _pop.contains(to)) return;
      _scheduleHide();
    });
    document.addEventListener("focusin",  (e) => { const b = btnOf(e.target); if (b && !_pinned) showInfo(b, false); });
    document.addEventListener("focusout", (e) => { if (btnOf(e.target) && !_pinned) _scheduleHide(); });
    document.addEventListener("click", (e) => {
      const b = btnOf(e.target); if (!b) return;
      if (_pinned && _cur === b) closeInfo(); else showInfo(b, true);       // click = pin (X closes); click again = close
    });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && _cur) closeInfo(); });
    window.addEventListener("resize", () => { if (_cur && _cur.isConnected) _place(); else closeInfo(); });
    window.addEventListener("scroll", () => { if (!_cur) return; if (!_cur.isConnected) closeInfo(); else if (_pinned) _place(); else closeInfo(); }, true);
  }
  bindInfo();

  return { load, get, setMeta, esc, metricsFor, defaultsFor, dirText, rangeText, recText,
           tableHTML, collect, compact, fillRecommended, summaryHTML, infoHTML, showInfo, closeInfo, infoState, bindInfo,
           timingPayload, timingConfirmText, applyTiming,
           context, resetContext, targets, barHTML, thrConfirmText, applyThr, inheritInfo };
})();
if (typeof module !== "undefined") module.exports = ThrUI;
