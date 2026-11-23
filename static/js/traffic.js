/* Net-monit V12 Traffic Analyzer front end. Plain JS, no libraries; every number comes from /api/traffic/*. */
(function () {
"use strict";
const API = "/api/traffic", $ = id => document.getElementById(id), qs = (s, r) => (r || document).querySelector(s), qsa = (s, r) => [...(r || document).querySelectorAll(s)];
const THUMB = new URLSearchParams(location.search).get("thumb") === "1";
if (THUMB) document.documentElement.classList.add("tr-thumb");
const S = { tab: "overview", unit: "bytes", win: 300, sort: "bytes", status: null, ov: null, src: "device", page: 1, selConn: null, sounds: {}, lastNote: -1, advOpen: false, timer: null, settings: null };

const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ICON = {
  star: '<svg viewBox="0 0 24 24"><path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z"/></svg>',
  down: '<svg viewBox="0 0 24 24"><path d="M12 4v14M6 12l6 6 6-6"/></svg>', up: '<svg viewBox="0 0 24 24"><path d="M12 20V6M6 12l6-6 6 6"/></svg>',
  trash: '<svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>', dl: '<svg viewBox="0 0 24 24"><path d="M12 3v12M7 11l5 5 5-5M5 20h14"/></svg>'
};

async function j(path, opts) {
  opts = opts || {};
  const h = authHeaders(); if (opts.formData) delete h["Content-Type"];
  const r = await fetch(API + path, { method: opts.method || "GET", headers: h, body: opts.formData ? opts.formData : (opts.body ? JSON.stringify(opts.body) : undefined) });
  let d = {}; try { d = await r.json(); } catch (_) {}
  if (r.status === 401 || r.status === 403) { if (d && d.error) showToast(d.error, "error"); }
  d._ok = r.ok; d._status = r.status; return d;
}

/* ------------------------------------------------------------- formatting */
function fmt(n, unit) {
  n = Number(n) || 0;
  if (unit === "packets") return n >= 1e6 ? (n / 1e6).toFixed(2) + " M" : n >= 1e4 ? (n / 1e3).toFixed(1) + " k" : String(Math.round(n));
  if (unit === "bits") n *= 8;
  const u = unit === "bits" ? ["bit", "kbit", "Mbit", "Gbit", "Tbit"] : ["B", "kB", "MB", "GB", "TB"];
  let i = 0; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return (i === 0 ? Math.round(n) : n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2)) + " " + u[i];
}
const rate = (n, unit) => fmt(n, unit) + (unit === "packets" ? "/s" : "/s");
const dur = s => { s = Math.max(0, Math.floor(s)); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60); return h ? `${h} h ${m} min` : m ? `${m} min ${s % 60} s` : `${s} s`; };
const clock = t => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const stamp = t => t ? new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
const flag = (cc, name) => cc ? `<img class="tr-flag" src="/static/flags/${esc(cc.toLowerCase())}.svg" alt="${esc(name || cc)}" title="${esc(name || cc)}" onerror="this.style.visibility='hidden'">` : '<span class="tr-flag"></span>';
const cat = c => `<img class="tr-cat" src="/static/img/svc/${esc(c || "network")}.svg" alt="" title="${esc(c || "")}" onerror="this.style.visibility='hidden'">`;
const star = (on, kind, value) => `<button class="tr-star${on ? " on" : ""}" data-fav="${kind}" data-val="${esc(value)}" aria-pressed="${on}" aria-label="${on ? "Remove from" : "Add to"} favorites: ${esc(value)}" title="${on ? "Remove from favorites" : "Add to favorites"}">${ICON.star}</button>`;

/* ------------------------------------------------------------- tabs, status */
function showTab(t) {
  S.tab = t;
  qsa(".tr-tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === t));
  qsa(".tr-pane").forEach(p => p.hidden = p.id !== "pane-" + t);
  if (t === "connections") loadConns();
  if (t === "notifications") loadNotif();
  if (t === "history") loadHistory();
  if (t === "settings") loadSettings();
  if (t === "overview") drawChart();
}
qsa(".tr-tabs button").forEach(b => b.onclick = () => showTab(b.dataset.tab));

function applyStatus(s) {
  S.status = s; const st = s.state || "idle";
  const chip = $("tr-state"); chip.className = "tr-state " + st; chip.textContent = { idle: "Idle", running: "Capturing", paused: "Paused", finished: "Finished", stopped: "Stopped", failed: "Stopped (error)" }[st] || st;
  const live = st === "running" || st === "paused";
  $("tr-btn-pause").hidden = !(live && s.source && s.source.type !== "pcap" || st === "paused"); $("tr-btn-pause").textContent = st === "paused" ? "Resume" : "Pause";
  $("tr-btn-stop").hidden = !live; $("tr-capture-body").hidden = live; $("tr-running-line").hidden = !live && !s.source;
  $("tr-btn-start").disabled = live;
  const src = s.source || {};
  $("tr-running-line").textContent = (src.name ? `${src.type === "device" ? "Network card" : src.type === "pcap" ? "File" : "Collector"}: ${src.name}` : "") +
    (src.bpf ? `   Filter: ${src.bpf} (${s.filter_mode})` : "") + (s.totals ? `   ${s.totals.packets_seen.toLocaleString()} packets` : "");
  const e = $("tr-err"); const msg = s.error || (s.programs_error && live && src.type === "device" ? "" : "");
  e.hidden = !msg; e.textContent = msg || "";
  const n = $("tr-note"); n.hidden = !s.note; n.textContent = s.note || "";
  $("ov-empty").hidden = !!(s.totals); $("ov-live").hidden = !s.totals;
  if (s.latest_notification_id !== undefined) checkNotifications(s.latest_notification_id);
}

async function refreshStatus() {
  const s = await j("/status");
  if (s._ok) applyStatus(s);
  else showStatusProblem("Cannot read the capture status (HTTP " + s._status + "). " + (s.error || "Press Reset capture, then Start again."));   // V12.4: never stay silent
  return s;
}
function showStatusProblem(text) {
  const er = $("tr-err"); er.hidden = false; er.textContent = text; $("tr-btn-reset").hidden = false;
}

/* ------------------------------------------------------------- capture start/stop */
qsa(".tr-seg[role=tablist] button").forEach(b => b.onclick = () => {
  S.src = b.dataset.src; qsa(".tr-seg[role=tablist] button").forEach(x => x.classList.toggle("on", x === b));
  qsa("[data-for]").forEach(el => el.hidden = !el.dataset.for.split(" ").includes(S.src));
});
qsa("[data-bpf]").forEach(a => a.onclick = ev => { ev.preventDefault(); $("tr-bpf").value = a.dataset.bpf; });

async function loadInterfaces() {
  const r = await j("/interfaces"); const sel = $("tr-iface"); if (!r._ok) return;
  const list = r.interfaces || [];
  sel.innerHTML = list.map(i => `<option value="${esc(i.name)}">${esc(i.name)}${i.description && i.description !== i.name ? " - " + esc(i.description) : ""}${i.addresses.length ? "  (" + esc(i.addresses.map(a => a.addr).join(", ")) + ")" : ""}</option>`).join("");
  const pref = list.find(i => i.addresses.some(a => /^\d+\.\d+\.\d+\.\d+$/.test(a.addr) && !a.addr.startsWith("127.") && !a.addr.startsWith("169.254.")));
  if (pref) sel.value = pref.name;
}

$("tr-btn-reset").onclick = async () => {
  if (!confirm("Stop whatever is running and clear the capture state? Saved history is kept.")) return;
  const r = await j("/reset", { method: "POST" }); $("tr-btn-reset").hidden = true; $("tr-err").hidden = true; $("tr-start-msg").textContent = "";
  if (r.status) applyStatus(r.status); else refreshStatus(); showToast("Capture state cleared. You can start a new capture now.", "info");
};
$("tr-btn-start").onclick = async () => {
  const msg = $("tr-start-msg"); msg.textContent = ""; let body = { type: S.src, bpf: $("tr-bpf").value.trim() };
  if (S.src === "device") { body.iface = $("tr-iface").value; body.export_pcap = $("tr-export").checked; }
  else if (S.src === "flows") { body.port = parseInt($("tr-flow-port").value, 10); body.allow = $("tr-flow-allow").value.split(",").map(x => x.trim()).filter(Boolean); }
  else {
    const f = $("tr-pcap-file").files[0]; if (!f) { msg.textContent = "Choose a capture file first."; return; }
    msg.textContent = "Uploading…"; const fd = new FormData(); fd.append("file", f);
    const u = await j("/pcap-upload", { method: "POST", formData: fd });
    if (!u._ok) { msg.textContent = u.error || "Upload failed."; return; }
    body.path = u.path;
  }
  $("tr-btn-start").disabled = true; msg.textContent = "Starting…";
  const r = await j("/start", { method: "POST", body });
  $("tr-btn-start").disabled = false;
  if (!r._ok) {
    msg.textContent = r.error || "Could not start."; $("tr-err").hidden = false; $("tr-err").textContent = r.error || "";
    if (/already running/i.test(r.error || "")) { $("tr-btn-reset").hidden = false; refreshStatus(); }      // V12.4: a stuck capture can always be cleared
    return;
  }
  $("tr-btn-reset").hidden = true;
  msg.textContent = ""; $("tr-err").hidden = true; S.ov = null; applyStatus(r.status); showTab("overview"); poll();
};
$("tr-btn-stop").onclick = async () => { const r = await j("/stop", { method: "POST" }); if (r.status) applyStatus(r.status); poll(); };
$("tr-btn-pause").onclick = async () => { const on = S.status && S.status.state !== "paused"; const r = await j("/pause", { method: "POST", body: { on } }); if (r.status) applyStatus(r.status); };
$("tr-btn-mini").onclick = () => window.open("/traffic?thumb=1", "nmtrafficmini", "width=380,height=300,menubar=no,toolbar=no,location=no,status=no");

/* ------------------------------------------------------------- overview */
qsa("#ov-unit button").forEach(b => b.onclick = () => { S.unit = b.dataset.v; qsa("#ov-unit button").forEach(x => x.classList.toggle("on", x === b)); renderOverview(); });
qsa("#ov-sort button").forEach(b => b.onclick = () => { S.sort = b.dataset.v; qsa("#ov-sort button").forEach(x => x.classList.toggle("on", x === b)); poll(); });
$("ov-win").onchange = () => { S.win = parseInt($("ov-win").value, 10); poll(); };

async function loadOverview() {
  const r = await j(`/overview?top=12&sort=${S.sort}&series=${S.win}`);
  if (!r._ok) return; S.ov = r; renderOverview();
}

function listHTML(items, kind) {
  if (!items || !items.length) return '<div class="tr-empty small">Nothing yet.</div>';
  const max = Math.max(1, ...items.map(i => S.sort === "packets" ? i.packets : i.bytes));
  return items.map(i => {
    const tot = (S.sort === "packets" ? i.packets : i.bytes), ratio = Math.max(2, tot / max * 100), inP = (S.sort === "packets" ? i.in_packets : i.in_bytes) / (tot || 1) * 100;
    let icon, name, sub = "", key, link;
    if (kind === "hosts") { icon = flag(i.country, i.country_name); name = i.name; sub = [i.asn_name, i.n_addresses > 1 ? i.n_addresses + " addresses" : "", i.bogon ? i.bogon : ""].filter(Boolean).join(" · "); key = i.name; link = ["domain", "=" + i.name]; }
    else if (kind === "services") { icon = cat(i.category); name = i.name === "?" ? "Unknown" : i.name === "-" ? "Not applicable" : i.name; sub = i.category; key = i.name; link = ["service", "=" + i.name]; }
    else if (kind === "programs") { icon = cat("management"); name = i.name; key = i.name; link = ["app", "=" + i.name]; }
    else { icon = flag(i.code, i.name); name = i.name || i.code; sub = i.hosts + (i.hosts === 1 ? " host" : " hosts"); key = null; link = ["country", "=" + i.code]; }
    const tags = (i.device ? `<span class="tr-tag dev" title="This address is a monitored Net-monit device">${esc(i.device)}</span>` : "") + (i.local ? '<span class="tr-tag">local</span>' : "");
    const fav = key && kind !== "countries" ? star(i.favorite, kind.slice(0, -1), key) : "<span></span>";
    return `<div class="tr-item">${icon}<div class="nm"><a href="#" data-link="${esc(link[0])}" data-lv="${esc(link[1])}" title="Show the connections of ${esc(name)}">${esc(name)}</a>${tags}${sub ? `<small>${esc(sub)}</small>` : ""}</div>` +
           `<div class="tr-bar" style="width:${ratio}%" title="Incoming ${fmt(S.sort === "packets" ? i.in_packets : i.in_bytes, S.sort === "packets" ? "packets" : S.unit)}, outgoing ${fmt(S.sort === "packets" ? i.out_packets : i.out_bytes, S.sort === "packets" ? "packets" : S.unit)}"><i class="i" style="width:${inP}%"></i><i class="o" style="width:${100 - inP}%"></i></div>` +
           `<div class="val">${fmt(S.sort === "packets" ? i.packets : i.bytes, S.sort === "packets" ? "packets" : S.unit)}</div>${fav}</div>`;
  }).join("");
}

function renderOverview() {
  const o = S.ov; if (!o || !o.active) return;
  const u = S.unit;
  $("t-in-now").textContent = rate(u === "packets" ? o.last_second.in_packets : o.last_second.in_bytes, u);
  $("t-out-now").textContent = rate(u === "packets" ? o.last_second.out_packets : o.last_second.out_bytes, u);
  $("t-in").textContent = fmt(u === "packets" ? o.totals.in_packets : o.totals.in_bytes, u); $("t-out").textContent = fmt(u === "packets" ? o.totals.out_packets : o.totals.out_bytes, u);
  $("t-conn").textContent = o.connections.toLocaleString(); $("t-hosts").textContent = o.hosts_count.toLocaleString(); $("t-bl").textContent = o.blacklisted; $("t-time").textContent = dur(o.elapsed);
  for (const k of ["hosts", "services", "programs", "countries"]) $("l-" + k).innerHTML = listHTML(o[k], k);
  drawChart();
}

/* chart: incoming above the line, outgoing below it */
let hoverX = null;
function drawChart() {
  const cv = $("ov-chart"); if (!cv || !S.ov || !S.ov.series) return;
  const dpr = window.devicePixelRatio || 1, w = cv.clientWidth, h = cv.clientHeight; if (!w) return;
  cv.width = w * dpr; cv.height = h * dpr; const c = cv.getContext("2d"); c.scale(dpr, dpr); c.clearRect(0, 0, w, h);
  const css = getComputedStyle(document.documentElement), col = n => css.getPropertyValue(n).trim() || "#888";
  const cIn = col("--status-ok"), cOut = col("--accent"), cText = col("--text-muted"), cGrid = col("--border");
  const unit = S.unit, key = unit === "packets" ? ["in_packets", "out_packets"] : ["in_bytes", "out_bytes"], mul = unit === "bits" ? 8 : 1;
  const ser = S.ov.series, n = Math.max(ser.length, 2), padL = 64, padR = 10, padT = 10, padB = 22, W = w - padL - padR, H = h - padT - padB, mid = padT + H / 2;
  let max = 1; ser.forEach(s => { max = Math.max(max, s[key[0]] * mul, s[key[1]] * mul); });
  const nice = (() => { const p = Math.pow(10, Math.floor(Math.log10(max))); const m = max / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p; })();
  c.font = "11px system-ui, sans-serif"; c.fillStyle = cText; c.strokeStyle = cGrid; c.lineWidth = 1; c.textAlign = "right";
  for (const f of [1, 0.5, 0, -0.5, -1]) {
    const y = mid - f * H / 2; c.beginPath(); c.moveTo(padL, y + .5); c.lineTo(w - padR, y + .5); c.globalAlpha = f === 0 ? 1 : .45; c.stroke(); c.globalAlpha = 1;
    c.fillText(fmt(Math.abs(f) * nice / (unit === "bits" ? 8 : 1), unit), padL - 8, y + 4);
  }
  const x = i => padL + (i / (n - 1)) * W, area = (k, color, sign) => {
    c.beginPath(); c.moveTo(x(0), mid);
    ser.forEach((s, i) => c.lineTo(x(i), mid - sign * (s[k] * mul / nice) * H / 2));
    c.lineTo(x(ser.length - 1), mid); c.closePath(); c.globalAlpha = .28; c.fillStyle = color; c.fill(); c.globalAlpha = 1;
    c.beginPath(); ser.forEach((s, i) => { const yy = mid - sign * (s[k] * mul / nice) * H / 2; i ? c.lineTo(x(i), yy) : c.moveTo(x(i), yy); }); c.strokeStyle = color; c.lineWidth = 1.6; c.stroke();
  };
  area(key[0], cIn, 1); area(key[1], cOut, -1);
  c.fillStyle = cText; c.textAlign = "center";
  [0, .25, .5, .75, 1].forEach(f => { const i = Math.round(f * (ser.length - 1)); if (ser[i]) c.fillText(clock(ser[i].t), padL + f * W, h - 6); });
  const hv = $("ov-hover");
  if (hoverX != null && ser.length > 1) {
    const i = Math.max(0, Math.min(ser.length - 1, Math.round((hoverX - padL) / W * (ser.length - 1)))), s = ser[i];
    c.strokeStyle = cText; c.beginPath(); c.moveTo(x(i) + .5, padT); c.lineTo(x(i) + .5, padT + H); c.stroke();
    hv.textContent = `${clock(s.t)}   in ${rate(s[key[0]], unit)}   out ${rate(s[key[1]], unit)}`;
  } else hv.textContent = "";
  cv.setAttribute("aria-label", `Incoming and outgoing traffic per second. Now: incoming ${rate(ser.length ? ser[ser.length - 1][key[0]] : 0, unit)}, outgoing ${rate(ser.length ? ser[ser.length - 1][key[1]] : 0, unit)}.`);
}
$("ov-chart").addEventListener("mousemove", e => { hoverX = e.offsetX; drawChart(); });
$("ov-chart").addEventListener("mouseleave", () => { hoverX = null; drawChart(); });
window.addEventListener("resize", drawChart);

/* click on a list entry or a star (event delegation) */
document.addEventListener("click", async e => {
  const a = e.target.closest("[data-link]");
  if (a) { e.preventDefault(); clearFilters(false); const el = qs(`[data-f="${a.dataset.link}"]`); if (el) el.value = a.dataset.lv; S.advOpen = true; $("f-adv").hidden = false; S.page = 1; showTab("connections"); return; }
  const f = e.target.closest("[data-fav]");
  if (f) {
    e.preventDefault(); e.stopPropagation(); const on = f.classList.contains("on");
    const r = await j("/favorites", { method: on ? "DELETE" : "POST", body: { kind: f.dataset.fav, value: f.dataset.val } });
    if (r._ok) { showToast(on ? "Removed from favorites" : "Added to favorites", "success"); if (S.tab === "overview") loadOverview(); else loadConns(); }
  }
});

/* ------------------------------------------------------------- connections */
function filters() {
  const p = new URLSearchParams(); const q = $("f-q").value.trim(); if (q) p.set("q", q);
  qsa("[data-f]").forEach(el => { const v = el.type === "checkbox" ? (el.checked ? "1" : "") : el.value.trim(); if (v) p.set(el.dataset.f, v); });
  p.set("sort", $("f-sort").value); p.set("page", S.page); return p;
}
function clearFilters(reload) { $("f-q").value = ""; qsa("[data-f]").forEach(el => { if (el.type === "checkbox") el.checked = false; else el.value = ""; }); S.page = 1; if (reload !== false) loadConns(); }
let ctimer = null; const reloadSoon = () => { clearTimeout(ctimer); ctimer = setTimeout(() => { S.page = 1; loadConns(); }, 300); };
$("f-q").oninput = reloadSoon; $("f-sort").onchange = () => { S.page = 1; loadConns(); };
qsa("[data-f]").forEach(el => el.addEventListener(el.type === "checkbox" || el.tagName === "SELECT" ? "change" : "input", reloadSoon));
$("f-more").onclick = () => { S.advOpen = !S.advOpen; $("f-adv").hidden = !S.advOpen; };
$("f-clear").onclick = () => clearFilters(true);
$("c-prev").onclick = () => { if (S.page > 1) { S.page--; loadConns(); } };
$("c-next").onclick = () => { S.page++; loadConns(); };
$("f-csv").onclick = async e => { e.preventDefault(); await download("/export/report.csv", "net-monit-traffic-report.csv"); };

async function download(path, name) {
  const r = await fetch(API + path, { headers: authHeaders() });
  if (!r.ok) { let m = "Download failed."; try { m = (await r.json()).error || m; } catch (_) {} showToast(m, "error"); return; }
  const b = await r.blob(), a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

async function loadConns() {
  const r = await j("/connections?" + filters().toString()); if (!r._ok) return;
  const tb = qs("#c-table tbody"); S.page = r.page;
  $("c-empty").hidden = r.items.length > 0; $("c-empty").textContent = (S.status && S.status.totals) ? "No connections match these filters." : "Start a capture to see connections.";
  tb.innerHTML = r.items.map(c => {
    const src = c.src_port != null ? `${c.src_ip}:${c.src_port}` : c.src_ip, dst = c.dst_port != null ? `${c.dst_ip}:${c.dst_port}` : c.dst_ip;
    const sv = c.service === "?" ? "unknown" : c.service === "-" ? "" : c.service;
    return `<tr data-id="${c.id}" class="${S.selConn === c.id ? "sel" : ""}"><td>${star(c.favorite, "host", c.host)}</td><td>${esc(src)}</td><td>${esc(dst)}</td><td>${esc(c.proto)}${c.msgs && Object.keys(c.msgs)[0] ? ` <small class="tr-hint">${esc(Object.keys(c.msgs)[0])}</small>` : ""}</td>` +
      `<td>${esc(sv)}</td><td>${flag(c.country, c.country_name)} ${esc(c.host)}${c.blacklisted ? '<span class="tr-tag bad">blacklisted</span>' : ""}${c.device ? `<span class="tr-tag dev">${esc(c.device)}</span>` : ""}</td>` +
      `<td>${esc(c.program || "")}</td><td class="num">${fmt(c.bytes, S.unit === "packets" ? "bytes" : S.unit)}</td><td class="num">${c.packets.toLocaleString()}</td><td>${clock(c.last)}</td></tr>`;
  }).join("");
  $("c-page").textContent = `Page ${r.page} of ${r.pages}`; $("c-prev").disabled = r.page <= 1; $("c-next").disabled = r.page >= r.pages; $("c-total").textContent = `${r.total.toLocaleString()} connections`;
}
qs("#c-table tbody").addEventListener("click", e => { if (e.target.closest("[data-fav]")) return; const tr = e.target.closest("tr[data-id]"); if (tr) openConn(parseInt(tr.dataset.id, 10)); });

async function openConn(id) {
  S.selConn = id; qsa("#c-table tbody tr").forEach(t => t.classList.toggle("sel", parseInt(t.dataset.id, 10) === id));
  const d = await j("/connections/" + id), box = $("c-detail"); box.hidden = false;
  if (!d._ok) { box.innerHTML = `<p>${esc(d.error || "Not available.")}</p>`; return; }
  const dir = d.direction === "incoming" ? ICON.down + " Incoming" : ICON.up + " Outgoing";
  box.innerHTML = `<h3>${esc(d.host)}</h3><div class="tr-hint">${flag(d.country, d.country_name)} ${esc(d.country_name || "Location unknown")}${d.asn ? " · AS" + d.asn + " " + esc(d.asn_name) : ""}</div>
    <dl><dt>Connection</dt><dd>${esc(d.src_ip)}${d.src_port != null ? ":" + d.src_port : ""} → ${esc(d.dst_ip)}${d.dst_port != null ? ":" + d.dst_port : ""}</dd>
    <dt>Protocol</dt><dd>${esc(d.proto)}</dd><dt>Service</dt><dd>${d.service === "?" ? "unknown" : d.service === "-" ? "not applicable" : esc(d.service)} <span class="tr-hint">${esc(d.category)}</span></dd>
    <dt>Direction</dt><dd>${dir}</dd><dt>Data</dt><dd>${fmt(d.bytes, "bytes")} in ${d.packets.toLocaleString()} packets</dd>
    <dt>First seen</dt><dd>${stamp(d.first)}</dd><dt>Last seen</dt><dd>${stamp(d.last)}</dd><dt>Duration</dt><dd>${dur(d.duration)}</dd>
    ${d.program ? `<dt>Program</dt><dd>${esc(d.program)}</dd>` : ""}${d.device ? `<dt>Net-monit device</dt><dd>${esc(d.device)}</dd>` : ""}
    ${d.src_mac ? `<dt>MAC</dt><dd>${esc(d.src_mac)} → ${esc(d.dst_mac || "?")}</dd>` : ""}${d.vlan != null ? `<dt>VLAN</dt><dd>${d.vlan}</dd>` : ""}
    ${Object.keys(d.msgs || {}).length ? `<dt>Messages</dt><dd>${Object.entries(d.msgs).map(([k, v]) => esc(k) + " ×" + v).join(", ")}</dd>` : ""}
    ${d.blacklisted ? '<dt>Blacklist</dt><dd><span class="tr-tag bad">address is blacklisted</span></dd>' : ""}<dt>Latency</dt><dd id="d-lat">not measured</dd></dl>
    <div class="btns"><button class="btn secondary small" id="d-ping">Measure latency to ${esc(d.remote)}</button>${d.service && d.service !== "?" && d.service !== "-" ? `<button class="btn secondary small" data-fav="service" data-val="${esc(d.service)}">Favorite service</button>` : ""}${d.program ? `<button class="btn secondary small" data-fav="program" data-val="${esc(d.program)}">Favorite program</button>` : ""}<button class="btn secondary small" data-fav="host" data-val="${esc(d.host)}">Favorite host</button><button class="btn secondary small" id="d-close">Close</button></div>`;
  $("d-close").onclick = () => { box.hidden = true; S.selConn = null; qsa("#c-table tbody tr.sel").forEach(t => t.classList.remove("sel")); };
  $("d-ping").onclick = async () => { $("d-lat").textContent = "measuring…"; const r = await j(`/connections/${id}/latency`, { method: "POST" }); $("d-lat").textContent = r.reachable ? `${r.latency_ms} ms (average of 3 pings)` : (r.error || "no reply (the host may block ping)"); };
}

/* ------------------------------------------------------------- notifications */
function fillSounds(list) { qsa("select[data-sound]").forEach(s => s.innerHTML = list.map(x => `<option value="${x}">${x === "none" ? "No sound" : x}</option>`).join("")); }
async function loadNotif() {
  const r = await j("/notifications/settings"); if (!r._ok) return; const s = r.settings; fillSounds(r.sounds);
  $("n-data-on").checked = s.data.enabled; $("n-data-th").value = s.data.threshold; $("n-data-unit").value = s.data.unit; $("n-data-sound").value = s.data.sound;
  $("n-fav-on").checked = s.favorite.enabled; $("n-fav-sound").value = s.favorite.sound; $("n-bl-on").checked = s.blacklist.enabled; $("n-bl-sound").value = s.blacklist.sound;
  $("n-vol").value = s.volume; $("n-vol-out").textContent = s.volume + "%"; S.volume = s.volume;
  $("n-mail-on").checked = s.email.enabled; $("n-mail-int").value = s.email.min_interval_sec; $("n-sms-on").checked = s.sms.enabled; $("n-sms-nums").value = s.sms.numbers.join("\n"); $("n-sms-int").value = s.sms.min_interval_sec;
  $("n-call-on").checked = s.call.enabled; $("n-call-nums").value = s.call.numbers.join("\n"); $("n-call-int").value = s.call.min_interval_sec; $("n-hook-on").checked = s.webhook.enabled; $("n-hook-url").value = s.webhook.url;
  loadLog();
}
$("n-vol").oninput = () => $("n-vol-out").textContent = $("n-vol").value + "%";
$("n-save").onclick = async () => {
  const lines = id => $(id).value.split("\n").map(x => x.trim()).filter(Boolean);
  const body = { volume: +$("n-vol").value, data: { enabled: $("n-data-on").checked, threshold: $("n-data-th").value, unit: $("n-data-unit").value, sound: $("n-data-sound").value },
    favorite: { enabled: $("n-fav-on").checked, sound: $("n-fav-sound").value }, blacklist: { enabled: $("n-bl-on").checked, sound: $("n-bl-sound").value },
    email: { enabled: $("n-mail-on").checked, min_interval_sec: +$("n-mail-int").value || 300 }, sms: { enabled: $("n-sms-on").checked, numbers: lines("n-sms-nums"), min_interval_sec: +$("n-sms-int").value || 600 },
    call: { enabled: $("n-call-on").checked, numbers: lines("n-call-nums"), min_interval_sec: +$("n-call-int").value || 1800 }, webhook: { enabled: $("n-hook-on").checked, url: $("n-hook-url").value.trim() } };
  const r = await j("/notifications/settings", { method: "POST", body }); $("n-msg").textContent = r._ok ? "Saved ✓" : (r.error || "Could not save"); if (r._ok) loadNotif(); setTimeout(() => $("n-msg").textContent = "", 3000);
};
$("n-test").onclick = async () => { await j("/notifications/test", { method: "POST" }); showToast("Test notification sent", "success"); setTimeout(loadLog, 800); };
$("n-clear").onclick = async () => { if (confirm("Clear the notification log?")) { await j("/notifications/log", { method: "DELETE" }); loadLog(); } };
async function loadLog() {
  const r = await j("/notifications/log?limit=100"); if (!r._ok) return;
  $("n-log").innerHTML = r.items.length ? `<table class="tr-table"><thead><tr><th>Time</th><th>Type</th><th>Message</th></tr></thead><tbody>${r.items.map(n => `<tr style="cursor:default"><td>${stamp(n.ts)}</td><td>${esc(n.kind)}</td><td style="white-space:normal;max-width:none"><b>${esc(n.title)}.</b> ${esc(n.text)}</td></tr>`).join("")}</tbody></table>` : '<div class="tr-empty small">No notifications yet.</div>';
}
function beep(name, vol) { if (!name || name === "none") return; try { const a = new Audio(`/static/sounds/${encodeURIComponent(name)}.mp3`); a.volume = Math.max(0, Math.min(1, (vol == null ? 50 : vol) / 100)); a.play().catch(() => {}); } catch (_) {} }
async function checkNotifications(latest) {
  if (S.lastNote < 0) { S.lastNote = latest; return; }
  if (latest > S.lastNote) {
    const r = await j("/notifications/log?since=" + S.lastNote + "&limit=20"); S.lastNote = latest;
    (r.items || []).reverse().forEach(n => { showToast(n.title + ": " + n.text, n.kind === "blacklist" ? "error" : "info", 8000); const sound = (n.data && n.data.sound); beep(sound, S.volume); });
    if (S.tab === "notifications") loadLog();
  }
}

/* ------------------------------------------------------------- history */
async function loadHistory() {
  const r = await j("/sessions"); if (!r._ok) return; const tb = qs("#h-table tbody");
  $("h-empty").hidden = r.sessions.length > 0;
  tb.innerHTML = r.sessions.map(s => `<tr data-sid="${s.id}"><td>${stamp(s.started_ts)}</td><td>${esc({ device: "Network card", pcap: "File", flows: "Collector" }[s.source_type] || s.source_type)}: ${esc(s.source_name)}</td><td>${esc(s.bpf || "")}</td><td>${esc(s.status)}</td>` +
    `<td class="num">${fmt(s.in_bytes, "bytes")}</td><td class="num">${fmt(s.out_bytes, "bytes")}</td><td class="num">${(s.connections || 0).toLocaleString()}</td><td><button class="tr-star" data-del="${s.id}" aria-label="Delete capture ${s.id}" title="Delete this capture"><span class="tr-icon">${ICON.trash}</span></button></td></tr>`).join("");
}
qs("#h-table tbody").addEventListener("click", async e => {
  const del = e.target.closest("[data-del]");
  if (del) { e.stopPropagation(); if (!confirm("Delete this capture and its saved connections?")) return; const r = await j("/sessions/" + del.dataset.del, { method: "DELETE" }); if (!r._ok) showToast(r.error || "Could not delete", "error"); $("h-detail").hidden = true; loadHistory(); return; }
  const tr = e.target.closest("tr[data-sid]"); if (!tr) return; const sid = tr.dataset.sid, d = await j("/sessions/" + sid), box = $("h-detail"); if (!d._ok) return; box.hidden = false;
  const tot = d.minutes.reduce((a, m) => a + m.in_bytes + m.out_bytes, 0), peak = d.minutes.reduce((a, m) => Math.max(a, (m.in_bytes + m.out_bytes) / 60), 0);
  box.innerHTML = `<h3>Capture ${sid}</h3><div class="tr-hint">${stamp(d.session.started_ts)} – ${d.session.ended_ts ? stamp(d.session.ended_ts) : "running"}</div>
    <dl><dt>Total</dt><dd>${fmt(tot, "bytes")}</dd><dt>Busiest minute</dt><dd>${fmt(peak, "bytes")}/s average</dd><dt>Connections saved</dt><dd>${d.connections.length}</dd></dl>
    <div class="btns"><button class="btn secondary small" id="h-csv">Download CSV</button>${d.session.pcap_path ? '<button class="btn secondary small" id="h-pcap">Download .pcap</button>' : ""}</div>
    <h4 style="margin:16px 0 6px;font-size:13px">Busiest connections</h4>${d.connections.slice(0, 8).map(c => `<div class="tr-hint" style="margin:3px 0">${esc(c.remote)} ${esc(c.proto)} ${esc(c.service === "?" ? "" : c.service)} · ${fmt(c.bytes, "bytes")}</div>`).join("")}`;
  $("h-csv").onclick = () => download("/export/report.csv?session=" + sid, `net-monit-traffic-${sid}.csv`);
  if ($("h-pcap")) $("h-pcap").onclick = () => download("/export/capture.pcap?session=" + sid, `net-monit-capture-${sid}.pcap`);
});

/* ------------------------------------------------------------- settings */
async function loadSettings() {
  const r = await j("/settings"); if (!r._ok) return; const s = r.settings; S.settings = s;
  $("s-country").value = s.country_db; $("s-asn").value = s.asn_db; $("s-bl").value = s.blacklist; $("s-rdns").checked = !!s.rdns; $("s-ret").value = s.retention_days; $("s-auto").checked = !!s.autostart;
  $("s-geo-status").textContent = `Country database: ${r.geo.country ? "loaded" : "not loaded"}.  AS database: ${r.geo.asn ? "loaded" : "not loaded"}.` + (r.geo.errors.length ? "  " + r.geo.errors.join(" ") : "");
  $("s-bl-status").textContent = r.blacklist.entries ? `${r.blacklist.entries.toLocaleString()} entries loaded from ${r.blacklist.path}` : "No blacklist loaded.";
}
$("s-bl-file").onchange = async () => {
  const f = $("s-bl-file").files[0]; if (!f) return; const fd = new FormData(); fd.append("file", f);
  const r = await j("/blacklist-upload", { method: "POST", formData: fd }); $("s-msg").textContent = r._ok ? `Blacklist loaded: ${r.entries} entries ✓` : (r.error || "Upload failed"); loadSettings();
};
$("s-save").onclick = async () => {
  let auto = null; const st = S.status;
  if ($("s-auto").checked) { if (st && st.source && (st.source.type === "device" || st.source.type === "flows") && (st.state === "running" || st.state === "paused")) auto = { type: st.source.type, iface: st.source.iface || st.source.name, bpf: st.source.bpf || "", port: st.source.port }; else if (S.settings && S.settings.autostart) auto = S.settings.autostart; else { $("s-msg").textContent = "Start a network-card or NetFlow capture first, then tick this box and save."; $("s-auto").checked = false; return; } }
  const r = await j("/settings", { method: "POST", body: { country_db: $("s-country").value.trim(), asn_db: $("s-asn").value.trim(), blacklist: $("s-bl").value.trim(), rdns: $("s-rdns").checked, retention_days: +$("s-ret").value || 30, autostart: auto } });
  $("s-msg").textContent = r._ok ? "Saved ✓" : (r.error || "Could not save"); loadSettings(); setTimeout(() => $("s-msg").textContent = "", 3500);
};

/* ------------------------------------------------------------- polling */
let busy = false;
async function poll() {
  if (busy) return; busy = true;
  try {
    const s = await refreshStatus();
    if (s && s.totals) { if (S.tab === "overview" || THUMB) await loadOverview(); else if (S.tab === "connections" && !$("f-q").matches(":focus")) await loadConns(); }
  } finally { busy = false; }
}
(async function init() {
  if (typeof requireAdminPage === "function") { /* provided by auth.js on pages that need it */ }
  await loadInterfaces(); fillSounds(["none", "pop", "gulp", "swhoosh"]);
  const s = await refreshStatus(); const n = await j("/notifications/settings"); if (n._ok) S.volume = n.settings.volume;
  if (s && s.totals) await loadOverview();
  poll(); S.timer = setInterval(poll, 1500);
  if (THUMB) { showTab("overview"); }
})();
})();
