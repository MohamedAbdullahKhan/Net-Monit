/**
 * dashboard.js — Net-monit V11.3
 * Copyright (c) 2024-2026 Abdullah · abuabdullah.be@outlook.com
 *
 * Features:
 *  - Live polling every 5 s via GET /api/status
 *  - Per-user persisted tile layout (position, size, hidden) via POST /api/dashboard/layout
 *  - Edit Layout mode: drag-to-reorder, size presets, corner drag-resize handle
 *  - Grid / List view toggle persisted per user
 *  - Grid density (2/3/4/5/Auto columns) persisted per user
 *  - All layout changes staged in memory during edit mode; committed on Save
 *  - Cancel reverts to the server state; Reset clears custom layout to the shared default
 */

/* ================================================================
   State
   ================================================================ */
let allDevices     = [];   // latest API response device list

// ── Auth callbacks (called by auth.js on login/logout) ────────────────────
window.onAdminLogout = function() {
  currentRole   = null;
  canEditLayout = false;
  // Cancel edit mode if active
  if (editMode) cancelEditMode();
  // Refresh dashboard immediately
  refresh();
};

window.onAdminLogin = function(role) {
  currentRole   = role;
  canEditLayout = true;
  refresh();
};

let currentRole    = null;
let canEditLayout  = false;
let editMode       = false;

// Staged layout changes (only committed on Save)
let stagedTiles    = {};   // { device_id: { position, hidden, size, grid_w, grid_h } }
let stagedView     = null; // 'grid' | 'list' | null (null = not changed)
let stagedCols     = null; // 0-5 | null

// Last known server-side prefs (used for Cancel/initialisation)
let serverViewType = 'grid';
let serverGridCols = 0;
let serverTiles    = {};   // same shape as stagedTiles

// Drag state
let dragSrcId    = null;
let ctxDeviceId  = null;

// Resize state
let resizeDev    = null;
let resizeStartX = 0;
let resizeStartY = 0;
let resizeOrigW  = 1;
let resizeOrigH  = 1;
const RESIZE_COL_PX = 240; // approximate column width in px

/* ================================================================
   Utility
   ================================================================ */
function tok() {
  return sessionStorage.getItem('netmon_session') || '';
}

function apiFetch(url, opts = {}) {
  return fetch(url, {
    ...opts,
    headers: { 'X-Session-Token': tok(), 'Content-Type': 'application/json', ...(opts.headers || {}) }
  });
}

// V10.1: showToast used to be redefined here too -- removed. auth.js
// (loaded on every page before this file, via base.html) is now the one
// place it's defined. See auth.js for why that matters, not just for
// tidiness.

/* ================================================================
   Boot & polling
   ================================================================ */
document.addEventListener('DOMContentLoaded', () => {
  restoreLastView();   // V11.3 patch 07: come back to the tab / filter you left
  refresh();
  setInterval(refresh, 5000);
  document.addEventListener('click', closeCtxMenu);
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closeCtxMenu(); if (editMode) cancelEditMode(); }
  });
  // Mouse-move and mouse-up for drag-resize
  document.addEventListener('mousemove', onResizeMove);
  document.addEventListener('mouseup', onResizeEnd);
});

async function refresh(retryCount = 0) {
  // During active edit, fetch new device data silently but don't re-render
  // (so drag positions are not lost mid-edit)
  if (editMode) {
    try {
      const res = await apiFetch('/api/status');
      if (res.ok) {
        const data = await res.json();
        allDevices = data.devices || [];
      }
    } catch(_) {}
    return;
  }

  const spinner = document.getElementById('refresh-spinner');
  if (spinner) spinner.style.display = '';

  try {
    const res = await apiFetch('/api/status');
    if (!res.ok) {
      // Do NOT silently give up and leave the page blank -- retry once
      // after a short delay (covers a transient network hiccup / the
      // server briefly not being reachable right after page load).
      if (retryCount < 2) {
        setTimeout(() => refresh(retryCount + 1), 1200);
        return;
      }
      if (spinner) spinner.style.display = 'none';
      return;
    }
    const data = await res.json();

    allDevices    = data.devices || [];
    currentRole   = data.role;
    // Any signed-in user (admin or viewer) may edit and save their OWN
    // dashboard layout. The backend never actually sent a distinct
    // "can_edit_layout" field (that was a dead reference that permanently
    // hid the Edit button) -- being logged in at all is the real condition.
    canEditLayout = !!data.role;

    // Sync server-side layout state
    serverViewType = data.view_type || 'grid';
    serverGridCols = data.grid_cols || 0;
    serverTiles    = buildServerTiles(allDevices);

    // Show/hide toolbar elements based on login state + role.
    // Edit + Add Tile are available to any signed-in user (Existing-Device
    // visibility toggling is meant for everyone; only the New-Device form
    // inside the Add Tile modal is admin-gated, enforced server-side by
    // POST /api/devices requiring admin).
    const btnEdit = document.getElementById('btn-edit-layout');
    const btnAdd  = document.getElementById('btn-add-tile');
    if (btnEdit) btnEdit.style.display = canEditLayout ? '' : 'none';
    if (btnAdd)  btnAdd.style.display  = !!currentRole ? '' : 'none';

    applyViewPrefs(serverViewType, serverGridCols);
    renderSummary(data.summary || {});
    renderIOCards(allDevices);
    updateCategoryTabs(allDevices);
    if (currentRole && !_cvLoaded) { _cvLoaded = true; loadCustomViews(); }

    const lu = document.getElementById('last-updated');
    if (lu) lu.textContent = 'Last updated: ' + new Date().toLocaleTimeString();
  } catch (_) {
    if (retryCount < 2) { setTimeout(() => refresh(retryCount + 1), 1200); return; }
  }

  if (spinner) spinner.style.display = 'none';
}

/* ================================================================
   V11.3 patch 07: remember the last tab/filter + custom views
   ================================================================ */
let customViews = [];
let _cvLoaded = false, _cvTabsSig = '', _lvTimer = null;
const _VALID_CAT = /^(all|network|firewall|windows|linux|url|cv:[a-z0-9]{1,12})$/, _VALID_SEV = /^(all|ok|warning|critical|offline)$/;
function _who() { return (sessionStorage.getItem('netmon_email') || 'anon').toLowerCase(); }
function _lsGet(k) { try { return localStorage.getItem(k); } catch (_) { return null; } }
function _lsSet(k, v) { try { localStorage.setItem(k, v); } catch (_) {} }

function restoreLastView() {
  try { const cv = JSON.parse(_lsGet('nm_dash_views_' + _who()) || '[]'); if (Array.isArray(cv)) customViews = cv; } catch (_) {}
  try {
    const lv = JSON.parse(_lsGet('nm_dash_last_' + _who()) || 'null');
    if (lv && _VALID_CAT.test(lv.cat || '')) currentCategory = lv.cat;
    if (lv && _VALID_SEV.test(lv.sev || '')) currentSeverity = lv.sev;
    if (!lv && tok()) restoreFromServer();
  } catch (_) {}
}
async function restoreFromServer() {          // first visit from this browser: pick up what you left on another PC
  try {
    const r = await apiFetch('/api/dashboard/last-view'); if (!r.ok) return;
    const lv = (await r.json()).last_view;
    if (lv && _VALID_CAT.test(lv.cat || '') && currentCategory === 'all' && currentSeverity === 'all') {
      currentCategory = lv.cat; currentSeverity = _VALID_SEV.test(lv.sev || '') ? lv.sev : 'all';
      if (allDevices.length) { renderSummary(summaryOf(allDevices)); updateCategoryTabs(allDevices); }
    }
  } catch (_) {}
}
function summaryOf(devs) { const s = { total: devs.length, ok: 0, warning: 0, critical: 0, offline: 0 }; devs.forEach(d => { if (s[d.status] !== undefined) s[d.status]++; }); return s; }
function saveLastView() {
  const v = { cat: currentCategory, sev: currentSeverity };
  _lsSet('nm_dash_last_' + _who(), JSON.stringify(v));
  if (!tok()) return;
  clearTimeout(_lvTimer);
  _lvTimer = setTimeout(() => { apiFetch('/api/dashboard/last-view', { method: 'POST', body: JSON.stringify(v) }).catch(() => {}); }, 500);
}

async function loadCustomViews() {
  try {
    const r = await apiFetch('/api/dashboard/custom-views'); if (!r.ok) return;
    customViews = (await r.json()).views || [];
    _lsSet('nm_dash_views_' + _who(), JSON.stringify(customViews));
    if (String(currentCategory).startsWith('cv:') && !customViews.some(v => 'cv:' + v.id === currentCategory)) currentCategory = 'all';
    _cvTabsSig = ''; updateCategoryTabs(allDevices);
  } catch (_) {}
}
function _worst(ids) {
  const r = { critical: 0, offline: 1, warning: 2, unknown: 3, ok: 4 }; let w = null;
  ids.forEach(id => { const d = allDevices.find(x => x.device_id === id); if (d && (w === null || (r[d.status] ?? 9) < (r[w] ?? 9))) w = d.status; });
  return w;
}
function renderCustomTabs(devices) {
  const host = document.getElementById('cv-tabs'); if (!host) return;
  const live = new Set((devices || []).map(d => d.device_id));
  const parts = customViews.map(v => {
    const n = v.device_ids.filter(i => live.has(i)).length, w = _worst(v.device_ids), cat = 'cv:' + v.id, act = currentCategory === cat;
    return { sig: cat + '|' + v.name + '|' + n + '|' + w + '|' + act, cat, v, n, w, act };
  });
  const sig = parts.map(p => p.sig).join(';') + '#' + (currentRole ? 1 : 0);
  if (sig === _cvTabsSig) return;
  _cvTabsSig = sig;
  host.innerHTML = parts.map(p =>
    '<button class="cat-tab cat-custom' + (p.act ? ' active' : '') + '" data-cat="' + p.cat + '" onclick="setCategory(\'' + p.cat + '\')" title="Custom view: ' + escHtml(p.v.name) + (p.v.priority ? ' (worst first)' : '') + '">' +
      '<span class="cv-star">&#9733;</span>' + escHtml(p.v.name) + ' <span class="cat-count">' + p.n + '</span>' +
      (p.w ? '<span class="dot ' + p.w + '" title="Worst state in this view: ' + statusLabel(p.w) + '"></span>' : '') + '</button>' +
    (p.act && currentRole ? '<button class="cat-tab cv-edit" onclick="openCustomViewEditor(\'' + p.v.id + '\')" title="Edit this view" aria-label="Edit view ' + escHtml(p.v.name) + '">&#9998;</button>' : '')
  ).join('') + (currentRole ? '<button class="cat-tab cv-add" onclick="openCustomViewEditor(null)" title="Create your own tab of the monitors you care about most">&#65291; Custom view</button>' : '');
}

/* ---- editor ---- */
let _cvEditId = null, _cvOrder = [];
function openCustomViewEditor(viewId, preselectDeviceId) {
  if (!currentRole) { showToast('Sign in to create custom views.', 'error'); return; }
  closeCtxMenu();
  const typeSel = document.getElementById('cv-type');
  const types = [...new Set(allDevices.map(d => (d.type || 'other')))].sort();
  typeSel.innerHTML = '<option value="">All types</option>' + types.map(t => '<option value="' + escHtml(t) + '">' + escHtml(t) + '</option>').join('');
  document.getElementById('cv-search').value = '';
  const pick = document.getElementById('cv-pick');
  pick.innerHTML = '<option value="">+ New view</option>' + customViews.map(v => '<option value="' + v.id + '">' + escHtml(v.name) + '</option>').join('');
  pick.value = viewId || ''; _cvEditId = viewId || null;
  cvLoadInto(_cvEditId);
  if (preselectDeviceId && !_cvOrder.includes(preselectDeviceId)) _cvOrder.push(preselectDeviceId);
  document.getElementById('cv-msg').textContent = '';
  cvRender();
  document.getElementById('cv-overlay').classList.remove('hidden');
  setTimeout(() => document.getElementById('cv-name').focus(), 50);
}
function cvLoadInto(id) {
  const v = customViews.find(x => x.id === id);
  document.getElementById('cv-name').value = v ? v.name : '';
  document.getElementById('cv-prio').checked = v ? !!v.priority : true;
  document.getElementById('cv-title').textContent = v ? 'Edit custom view' : 'New custom view';
  document.getElementById('cv-del').style.display = v ? '' : 'none';
  _cvOrder = v ? [...v.device_ids] : [];
}
function cvPick() { const keep = new Set(_cvOrder); _cvEditId = document.getElementById('cv-pick').value || null; cvLoadInto(_cvEditId); cvRender(); }
function closeCustomViewEditor() { document.getElementById('cv-overlay').classList.add('hidden'); }
function _cvShown() {
  const q = document.getElementById('cv-search').value.trim().toLowerCase(), t = document.getElementById('cv-type').value;
  return allDevices.filter(d => (!t || (d.type || 'other') === t) && (!q || (d.name + ' ' + (d.host || '') + ' ' + d.device_id + ' ' + (d.type || '')).toLowerCase().includes(q)))
                   .sort((a, b) => String(a.name).localeCompare(String(b.name)));
}
function cvRender() {
  const sel = new Set(_cvOrder), shown = _cvShown();
  document.getElementById('cv-list').innerHTML = shown.map(d =>
    '<label class="cv-item"><input type="checkbox" data-id="' + escHtml(d.device_id) + '"' + (sel.has(d.device_id) ? ' checked' : '') + ' onchange="cvToggle(this)">' +
    '<span class="dot ' + d.status + '"></span><span class="nm">' + escHtml(d.name) + '</span><span class="sub">' + escHtml(d.type || '') + (currentRole === 'admin' && d.host ? ' &middot; ' + escHtml(d.host) : '') + '</span></label>').join('')
    || '<div style="padding:14px;color:var(--text-muted);font-size:13px">No monitors match.</div>';
  document.getElementById('cv-count').textContent = _cvOrder.length + ' selected \u00b7 ' + shown.length + ' shown';
}
function cvToggle(cb) {
  const id = cb.getAttribute('data-id'), i = _cvOrder.indexOf(id);
  if (cb.checked && i < 0) _cvOrder.push(id); else if (!cb.checked && i >= 0) _cvOrder.splice(i, 1);
  document.getElementById('cv-count').textContent = _cvOrder.length + ' selected \u00b7 ' + _cvShown().length + ' shown';
}
function cvSelectShown(on) {
  _cvShown().forEach(d => { const i = _cvOrder.indexOf(d.device_id); if (on && i < 0) _cvOrder.push(d.device_id); if (!on && i >= 0) _cvOrder.splice(i, 1); });
  cvRender();
}
async function _cvPost(list, okMsg, goTo, keepOpen) {
  const msg = document.getElementById('cv-msg');
  try {
    const r = await apiFetch('/api/dashboard/custom-views', { method: 'POST', body: JSON.stringify({ views: list }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) { msg.className = 'cv-msg'; msg.textContent = j.error || ('Could not save (' + r.status + ')'); return false; }
    customViews = j.views; _lsSet('nm_dash_views_' + _who(), JSON.stringify(customViews)); _cvTabsSig = '';
    if (!keepOpen) closeCustomViewEditor();
    if (goTo) setCategory(goTo); else { if (String(currentCategory).startsWith('cv:') && !customViews.some(v => 'cv:' + v.id === currentCategory)) setCategory('all'); else updateCategoryTabs(allDevices); }
    showToast(okMsg, 'success'); return true;
  } catch (e) { msg.className = 'cv-msg'; msg.textContent = 'Could not save: ' + e.message; return false; }
}
async function saveCustomView(closeAfter) {
  const name = document.getElementById('cv-name').value.trim(), msg = document.getElementById('cv-msg');
  if (!name) { msg.className = 'cv-msg'; msg.textContent = 'Give the view a name.'; return; }
  if (!_cvOrder.length) { msg.className = 'cv-msg'; msg.textContent = 'Tick at least one monitor.'; return; }
  const v = { id: _cvEditId || '', name, device_ids: [..._cvOrder], priority: document.getElementById('cv-prio').checked };
  const list = _cvEditId ? customViews.map(x => x.id === _cvEditId ? Object.assign({}, x, v, { id: x.id }) : x) : customViews.concat([v]);
  const before = new Set(customViews.map(x => x.id));
  const keep = closeAfter === false;   // plain Save keeps the editor open, Save & close (or no argument) closes it
  const ok = await _cvPost(list, 'Custom view saved \u2713', null, keep);
  if (ok) {
    const made = customViews.find(x => !before.has(x.id)), id = _cvEditId || (made && made.id) || customViews[customViews.length - 1].id;
    setCategory('cv:' + id);
    if (keep) { _cvEditId = id; const p = document.getElementById('cv-pick'); p.innerHTML = '<option value="">+ New view</option>' + customViews.map(v => '<option value="' + v.id + '">' + escHtml(v.name) + '</option>').join(''); p.value = id; document.getElementById('cv-title').textContent = 'Edit custom view'; document.getElementById('cv-del').style.display = ''; const m = document.getElementById('cv-msg'); m.className = 'cv-msg ok'; m.textContent = 'Saved \u2713'; }
  }
}
async function deleteCustomView() {
  const v = customViews.find(x => x.id === _cvEditId); if (!v) return;
  if (!confirm('Delete the custom view "' + v.name + '"? The monitors themselves are not touched.')) return;
  await _cvPost(customViews.filter(x => x.id !== v.id), 'Custom view deleted');
}
function menuAddToCustomView() {
  const id = ctxDeviceId; closeCtxMenu();
  const active = String(currentCategory).startsWith('cv:') ? currentCategory.slice(3) : null;
  openCustomViewEditor(active || (customViews.length === 1 ? customViews[0].id : null), id);
}
async function menuRemoveFromView() {
  const id = ctxDeviceId; closeCtxMenu();
  const vid = String(currentCategory).startsWith('cv:') ? currentCategory.slice(3) : null; if (!vid) return;
  const list = customViews.map(v => v.id === vid ? Object.assign({}, v, { device_ids: v.device_ids.filter(x => x !== id) }) : v).filter(v => v.device_ids.length);
  const r = await apiFetch('/api/dashboard/custom-views', { method: 'POST', body: JSON.stringify({ views: list }) });
  const j = await r.json().catch(() => ({}));
  if (r.ok && j.ok) { customViews = j.views; _lsSet('nm_dash_views_' + _who(), JSON.stringify(customViews)); _cvTabsSig = ''; if (!customViews.some(v => 'cv:' + v.id === currentCategory)) setCategory('all'); else { updateCategoryTabs(allDevices); } showToast('Removed from this view', 'success'); }
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeCustomViewEditor(); });

/* ================================================================
   V7.2: Infrastructure Overview telemetry cards (NISM-inspired)
   ================================================================ */
async function renderIOCards(devices) {
  // -- Network device counts --
  const netDevices = devices.filter(d => (d.method || '') !== 'url');
  const onlineNet  = netDevices.filter(d => d.status === 'ok' || d.status === 'warning').length;
  const offlineNet = netDevices.filter(d => d.status === 'critical' || d.status === 'offline').length;

  const elDevOnline = document.getElementById('io-devices-online');
  const elDevTotal  = document.getElementById('io-devices-total');
  const elDevMsg    = document.getElementById('io-devices-msg');
  if (elDevOnline) elDevOnline.innerHTML = onlineNet + ' <span class="io-card-unit">/ ' + netDevices.length + ' Online</span>';
  if (elDevMsg) {
    if (offlineNet > 0) {
      elDevMsg.textContent = offlineNet + ' node(s) unreachable';
      elDevMsg.className = 'io-card-sub crit';
    } else {
      elDevMsg.textContent = netDevices.length ? 'All nodes reporting online' : 'No devices added yet';
      elDevMsg.className = 'io-card-sub';
    }
  }

  // -- Web application counts (method === 'url') --
  const urlDevices = devices.filter(d => (d.method || '') === 'url');
  const onlineApps = urlDevices.filter(d => d.status === 'ok').length;
  const failedApps = urlDevices.filter(d => d.status === 'critical' || d.status === 'offline').length;

  const elAppOnline = document.getElementById('io-apps-online');
  const elAppTotal  = document.getElementById('io-apps-total');
  const elAppMsg    = document.getElementById('io-apps-msg');
  if (elAppOnline) elAppOnline.innerHTML = onlineApps + ' <span class="io-card-unit">/ ' + urlDevices.length + ' Online</span>';
  if (elAppMsg) {
    if (failedApps > 0) {
      elAppMsg.textContent = failedApps + ' service outage active';
      elAppMsg.className = 'io-card-sub crit';
    } else {
      elAppMsg.textContent = urlDevices.length ? 'Web services fully healthy' : 'No web apps configured yet';
      elAppMsg.className = 'io-card-sub';
    }
  }

  // -- WAN speed (latest speed test result, cached to avoid refetch every poll) --
  const now = Date.now();
  if (!window._ioSpeedCache || (now - window._ioSpeedCache.ts) > 15000) {
    try {
      const r = await fetch('/api/speedtest/history?limit=1');
      const rows = await r.json();
      window._ioSpeedCache = { ts: now, data: rows[0] || null };
    } catch (_) { window._ioSpeedCache = { ts: now, data: null }; }
  }
  const latest = window._ioSpeedCache.data;
  const elDl = document.getElementById('io-download');
  const elUl = document.getElementById('io-upload');
  const elIsp = document.getElementById('io-isp');
  const elPing = document.getElementById('io-ping');
  if (latest) {
    if (elDl)  elDl.innerHTML  = (latest.download_mbps||0).toFixed(1) + ' <span class="io-card-unit">Mbps</span>';
    if (elUl)  elUl.innerHTML  = (latest.upload_mbps||0).toFixed(1) + ' <span class="io-card-unit">Mbps</span>';
    if (elIsp) elIsp.textContent = latest.isp ? ('ISP: ' + latest.isp) : 'Run a speed test to populate';
    if (elPing) elPing.textContent = 'Ping: ' + (latest.latency_ms!=null?latest.latency_ms.toFixed(0):'--') + ' ms';
  }
}

function buildServerTiles(devices) {
  const map = {};
  devices.forEach(d => {
    map[d.device_id] = {
      position: d.tile_position || 0,
      hidden:   !!d.tile_hidden,
      size:     d.tile_size || 'normal',
      grid_w:   d.tile_grid_w || 1,
      grid_h:   d.tile_grid_h || 1,
    };
  });
  return map;
}

/* ================================================================
   Summary bar
   V10.0: two fixes together since they're the same element --
   (1) pills were showing the raw lowercase status key ("ok") instead of
   statusLabel()'s friendly text ("Healthy") -- CSS text-transform was
   rendering it as "OK" on screen even though the underlying label was
   never actually fixed up, just visually capitalized.
   (2) pills are now clickable -- picking one filters the device grid
   below to just that severity, resetting the category-tab filter to
   "all" first so "click Warning, see every warning host" works exactly
   as literally described, not just within whatever category tab
   happened to be selected already. Click the same pill again, or the
   "total" pill, to clear the filter.
   ================================================================ */
let currentSeverity = 'all';

function renderSummary(summary) {
  const bar = document.getElementById('summary-bar');
  if (!bar) return;
  const colors = { ok:'#3DD68C', warning:'#F2B84B', critical:'#FF5C5C', offline:'#6B7280' };
  bar.innerHTML = Object.entries(colors).map(([s, c]) => `
    <div class="summary-pill${currentSeverity===s ? ' active' : ''}" data-sev="${s}" role="button" tabindex="0" title="Show ${statusLabel(s)} hosts">
      <span class="dot ${s}"></span>
      <span class="count" style="color:${c}">${summary[s] || 0}</span>
      <span class="label">${statusLabel(s)}</span>
    </div>`).join('') +
    `<div class="summary-pill${currentSeverity==='all' ? ' active' : ''}" data-sev="all" role="button" tabindex="0" title="Show all hosts">
      <span class="count">${summary.total || 0}</span>
      <span class="label">total</span>
    </div>`;

  bar.querySelectorAll('.summary-pill').forEach(pill => {
    const go = () => setSeverityFilter(pill.dataset.sev);
    pill.addEventListener('click', go);
    pill.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });
}

function setSeverityFilter(sev) {
  // Clicking the pill that's already active clears the filter instead of
  // re-applying it -- lets the same click act as an on/off toggle.
  currentSeverity = (currentSeverity === sev) ? 'all' : sev;
  if (!String(currentCategory).startsWith('cv:')) currentCategory = 'all';   // inside a custom view the severity filter narrows that view
  syncTabActive();
  document.querySelectorAll('.summary-pill').forEach(p => p.classList.toggle('active', p.dataset.sev === currentSeverity));
  renderDevices(_applyFilters(allDevices));
  saveLastView();
}

/* ================================================================
   View type & grid density
   ================================================================ */
function applyViewPrefs(viewType, cols) {
  const grid = document.getElementById('device-grid');
  if (!grid) return;

  // Switch grid ↔ list
  const isGrid = viewType !== 'list';
  grid.classList.toggle('dash-grid', isGrid);
  grid.classList.toggle('dashboard-list', !isGrid);

  // Density row visible only in grid view
  const densRow = document.getElementById('grid-density-row');
  if (densRow) densRow.style.display = isGrid ? '' : 'none';

  // Update view toggle buttons
  document.getElementById('btn-view-grid')?.classList.toggle('active', isGrid);
  document.getElementById('btn-view-list')?.classList.toggle('active', !isGrid);

  // Apply columns CSS variable
  if (isGrid) {
    if (cols && cols > 0) {
      grid.style.gridTemplateColumns = `repeat(${cols}, minmax(0, 1fr))`;
    } else {
      grid.style.gridTemplateColumns = '';
    }
  } else {
    grid.style.gridTemplateColumns = '';
  }

  // Highlight active density button
  document.querySelectorAll('[data-cols]').forEach(btn => {
    btn.classList.toggle('active', parseInt(btn.dataset.cols) === cols);
  });
}

function setViewType(vt) {
  if (editMode) {
    stagedView = vt;
    applyViewPrefs(vt, stagedCols ?? serverGridCols);
  } else {
    // Persist immediately if not in edit mode
    apiFetch('/api/dashboard/view-mode', {
      method: 'POST',
      body: JSON.stringify({ view_type: vt, grid_cols: serverGridCols })
    }).then(() => {
      serverViewType = vt;
      applyViewPrefs(vt, serverGridCols);
    });
  }
}

function setGridCols(n) {
  if (editMode) {
    stagedCols = n;
    applyViewPrefs(stagedView ?? serverViewType, n);
  } else {
    apiFetch('/api/dashboard/view-mode', {
      method: 'POST',
      body: JSON.stringify({ view_type: serverViewType, grid_cols: n })
    }).then(() => {
      serverGridCols = n;
      applyViewPrefs(serverViewType, n);
    });
  }
}

/* ================================================================
   Edit Layout mode
   ================================================================ */
function toggleEditMode() {
  if (!editMode && String(currentCategory).startsWith('cv:')) { showToast('Drag, resize and hide work on the main tabs. Use the pencil next to this view to change which tiles it holds.', 'info'); return; }
  editMode ? cancelEditMode() : enterEditMode();
}

function enterEditMode() {
  editMode = true;
  // Deep copy server tiles as the starting point for staging
  stagedTiles = JSON.parse(JSON.stringify(serverTiles));
  stagedView  = null;
  stagedCols  = null;

  const btn    = document.getElementById('btn-edit-layout');
  const banner = document.getElementById('edit-mode-banner');
  if (btn)    { btn.classList.add('edit-active'); btn.innerHTML = `
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
      <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
      <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
    </svg> Editing…`; }
  if (banner) banner.style.display = 'flex';

  const grid = document.getElementById('device-grid');
  if (grid) grid.classList.add('edit-mode');

  // Re-render: show hidden tiles (dimmed), add size presets + resize handles
  renderDevices(allDevices, true);
}

function cancelEditMode() {
  editMode    = false;
  stagedTiles = {};
  stagedView  = null;
  stagedCols  = null;

  const btn    = document.getElementById('btn-edit-layout');
  const banner = document.getElementById('edit-mode-banner');
  if (btn)    { btn.classList.remove('edit-active'); btn.innerHTML = `
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
      <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
    </svg> Edit Layout`; }
  if (banner) banner.style.display = 'none';

  const grid = document.getElementById('device-grid');
  if (grid) grid.classList.remove('edit-mode');

  applyViewPrefs(serverViewType, serverGridCols);
  renderDevices(allDevices, false);
}

async function saveLayout() {
  const btn = document.getElementById('btn-save-layout');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }

  // Build tiles list from staged state in current DOM order
  const grid = document.getElementById('device-grid');
  const cards = grid ? grid.querySelectorAll('.device-card[data-id]') : [];
  const tiles = [];
  let pos = 0;
  cards.forEach(card => {
    const did = card.dataset.id;
    const st  = stagedTiles[did] || serverTiles[did] || {};
    const colSpan = parseInt(card.style.getPropertyValue('--tile-w') || st.grid_w || 1);
    const rowSpan = parseInt(card.style.getPropertyValue('--tile-h') || st.grid_h || 1);
    tiles.push({
      device_id: did,
      position:  pos++,
      hidden:    !!st.hidden,
      size:      st.size || 'normal',
      grid_w:    colSpan,
      grid_h:    rowSpan,
    });
  });

  try {
    const body = { tiles };
    if (stagedView  !== null) body.view_type  = stagedView;
    if (stagedCols  !== null) body.grid_cols  = stagedCols;

    const res = await apiFetch('/api/dashboard/layout', { method: 'POST', body: JSON.stringify(body) });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    showToast('Layout saved!', 'success');

    // Sync server state and exit edit mode
    if (stagedView  !== null) serverViewType = stagedView;
    if (stagedCols  !== null) serverGridCols = stagedCols;
    // Trigger a fresh status poll to pick up the new server layout
    editMode = false;
    await refresh();
    cancelEditMode(); // cleans up UI state
  } catch (err) {
    showToast('Save failed: ' + err.message, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Save Layout'; }
  }
}

async function resetLayout() {
  if (!confirm('Reset to the shared default layout? Your custom layout will be cleared.')) return;
  try {
    await apiFetch('/api/dashboard/layout', { method: 'POST' });
    showToast('Layout reset to default.', 'info');
    cancelEditMode();
    await refresh();
  } catch (_) {
    showToast('Reset failed.', 'error');
  }
}

/* ================================================================
   Tile rendering
   ================================================================ */
function getTileState(deviceId) {
  return editMode
    ? (stagedTiles[deviceId] || serverTiles[deviceId] || { position:0, hidden:false, size:'normal', grid_w:1, grid_h:1 })
    : (serverTiles[deviceId]  || { position:0, hidden:false, size:'normal', grid_w:1, grid_h:1 });
}

const SIZE_LABELS = { normal:'1×1', wide:'2×1', tall:'1×2', large:'2×2', custom:'Custom' };
const SIZE_W = { normal:1, wide:2, tall:1, large:2, custom:1 };
const SIZE_H = { normal:1, wide:1, tall:2, large:2, custom:1 };

function applyTileSpan(card, size, grid_w, grid_h) {
  // Remove all preset classes first
  card.classList.remove('tile-normal','tile-wide','tile-tall','tile-large');
  const preset = ['normal','wide','tall','large'].includes(size) ? size : null;
  if (preset && preset !== 'custom') {
    card.classList.add('tile-' + preset);
    card.style.gridColumn = '';
    card.style.gridRow    = '';
  } else {
    // Custom: apply inline grid spans
    const w = grid_w || 1;
    const h = grid_h || 1;
    card.style.gridColumn = `span ${w}`;
    card.style.gridRow    = `span ${h}`;
  }
  // Store for later read during saveLayout
  card.style.setProperty('--tile-w', (SIZE_W[size] || grid_w || 1).toString());
  card.style.setProperty('--tile-h', (SIZE_H[size] || grid_h || 1).toString());
}

/* ================================================================
   V7.2: Category filter tabs (General / Network / Firewall / Windows /
   Linux / URL-Sites). Filters which tiles renderDevices shows; the IO
   summary cards above always reflect the full unfiltered device set.
   ================================================================ */
let currentCategory = 'all';
let _customOrder = null;   // device ids in the order a custom view wants (null on normal tabs)

function _deviceCategory(d) {
  const method = (d.method || '').toLowerCase();
  const type   = (d.type   || '').toLowerCase();
  if (method === 'url') return 'url';
  if (type === 'firewall') return 'firewall';
  if (type === 'windows' || method === 'powershell') return 'windows';
  if (type === 'linux'   || method === 'ssh') return 'linux';
  if (type === 'network' || type === 'wireless' || method === 'ping' || method === 'snmp') return 'network';
  return 'network';
}

function _applyFilters(devices) {
  _customOrder = null;
  if (String(currentCategory).startsWith('cv:')) {
    const v = customViews.find(x => 'cv:' + x.id === currentCategory);
    if (v) {
      const byId = new Map(devices.map(d => [d.device_id, d]));
      let out = v.device_ids.map(id => byId.get(id)).filter(Boolean).map(d => Object.assign({}, d, { tile_hidden: false }));   // added on purpose: never hidden here
      if (currentSeverity !== 'all') out = out.filter(d => d.status === currentSeverity);
      if (v.priority) { const r = { critical: 0, offline: 1, warning: 2, unknown: 3, ok: 4 }; out = out.map((d, i) => [d, i]).sort((a, b) => ((r[a[0].status] ?? 4) - (r[b[0].status] ?? 4)) || (a[1] - b[1])).map(x => x[0]); }
      _customOrder = out.map(d => d.device_id);
      return out;
    }
    if (!_cvLoaded) return currentSeverity === 'all' ? devices : devices.filter(d => d.status === currentSeverity);   // views still loading: keep the saved tab, show everything meanwhile
    currentCategory = 'all';   // that view was deleted
  }
  let out = currentCategory === 'all' ? devices : devices.filter(d => _deviceCategory(d) === currentCategory);
  if (currentSeverity !== 'all') out = out.filter(d => d.status === currentSeverity);
  return out;
}

function setCategory(cat) {
  currentCategory = cat;
  currentSeverity = 'all';
  syncTabActive();
  document.querySelectorAll('.summary-pill').forEach(p => p.classList.toggle('active', p.dataset.sev === 'all'));
  renderDevices(_applyFilters(allDevices));
  renderCustomTabs(allDevices);
  saveLastView();
}
function syncTabActive() {
  document.querySelectorAll('.cat-tab[data-cat]').forEach(btn => btn.classList.toggle('active', btn.dataset.cat === currentCategory));
}

function updateCategoryTabs(devices) {
  const counts = { all: devices.length, network: 0, firewall: 0, windows: 0, linux: 0, url: 0 };
  devices.forEach(d => { const c = _deviceCategory(d); if (counts[c] !== undefined) counts[c]++; });
  Object.keys(counts).forEach(cat => {
    const el = document.getElementById('cnt-' + cat);
    if (el) el.textContent = counts[cat];
  });
  // Re-render with fresh data through whichever filter (category and/or
  // severity) is currently active -- keeps the selection sticky across
  // every 5s poll instead of always snapping back to "all".
  renderDevices(_applyFilters(devices));
  renderCustomTabs(devices);
  syncTabActive();
}

function renderDevices(devices, forceShowHidden = false) {
  const grid = document.getElementById('device-grid');
  const empty = document.getElementById('empty-state');
  const note  = document.getElementById('hidden-tiles-note');
  if (!grid) return;

  // Sort by tile_position
  const sorted = _customOrder
    ? [...devices].sort((a, b) => _customOrder.indexOf(a.device_id) - _customOrder.indexOf(b.device_id))   // custom view: its own priority order
    : [...devices].sort((a, b) => (a.tile_position || 0) - (b.tile_position || 0));

  const visible  = sorted.filter(d => !d.tile_hidden);
  const hidden   = sorted.filter(d => !!d.tile_hidden);
  const showList = editMode ? sorted : visible;  // show ALL in edit mode (dimmed if hidden)

  const hiddenCount = hidden.length;
  if (note) {
    const show = hiddenCount > 0 && !editMode;
    note.style.display = show ? 'flex' : 'none';
    const hc = note.querySelector('.hidden-count');
    if (hc) hc.textContent = hiddenCount;
    const showBtn = document.getElementById('show-hidden-btn');
    if (showBtn) showBtn.onclick = () => {
      visible.concat(hidden).forEach(d => unHideTile(d.device_id));
    };
  }

  if (empty) empty.style.display = visible.length === 0 && !editMode ? '' : 'none';

  // Preserve existing card elements if device hasn't changed (just update metrics)
  const existing = {};
  grid.querySelectorAll('.device-card[data-id]').forEach(c => {
    existing[c.dataset.id] = c;
  });

  // Remove cards not in current list
  const currentIds = new Set(showList.map(d => d.device_id));
  Object.entries(existing).forEach(([id, c]) => {
    if (!currentIds.has(id)) c.remove();
  });

  showList.forEach((device, idx) => {
    const st = getTileState(device.device_id);
    let card = existing[device.device_id];
    if (!card) {
      card = buildTileCard(device);
      grid.appendChild(card);
    } else {
      updateTileCard(card, device);
    }
    // Apply size
    applyTileSpan(card, st.size, st.grid_w, st.grid_h);
    // Visual: dim hidden tiles in edit mode
    card.style.opacity = (editMode && st.hidden) ? '0.42' : '';
    // Re-apply size presets active state
    card.querySelectorAll('.tile-size-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.size === st.size);
    });
  });
  if (_customOrder) {   // keep the on-screen order = priority order as states change (only touches the DOM when it differs)
    const want = showList.map(d => d.device_id), have = [...grid.querySelectorAll('.device-card[data-id]')].map(c => c.dataset.id);
    if (want.join('|') !== have.join('|')) want.forEach(id => { const c = grid.querySelector('.device-card[data-id="' + (window.CSS && CSS.escape ? CSS.escape(id) : id) + '"]'); if (c) grid.appendChild(c); });
  }
}

function buildTileCard(device) {
  const card = document.createElement('div');
  card.className = 'device-card';
  card.dataset.id = device.device_id;
  card.draggable = true;
  card.innerHTML = tileInnerHTML(device);
  attachTileEvents(card, device);
  return card;
}

function updateTileCard(card, device) {
  // Patch only the dynamic parts (status, metrics, error) without re-creating the whole card
  // This preserves drag/resize listeners across polls
  const statusSel  = card.querySelector('.status-label');
  const dotSel     = card.querySelector('.dot');
  const metricSel  = card.querySelector('.metric-grid');
  const errorSel   = card.querySelector('.device-error');
  const footSel    = card.querySelector('.device-foot');

  if (statusSel) { statusSel.className = `status-label ${device.status}`; statusSel.textContent = statusLabel(device.status); }
  if (dotSel)    { dotSel.className = `dot ${device.status} pulse`; }
  if (metricSel) metricSel.innerHTML = buildMetricsHTML(device);
  if (errorSel)  { errorSel.textContent = device.last_error || ''; errorSel.style.display = device.last_error ? '' : 'none'; }
  if (footSel)   footSel.innerHTML  = buildFootHTML(device);

  card.className = `device-card ${device.status}`;
}

function tileInnerHTML(device) {
  const m = device.metrics || {};
  return `
    <!-- V7.2: size presets shown in edit mode -->
    <div class="tile-size-presets">
      ${['normal','wide','tall','large'].map(s => `
        <button class="tile-size-btn${(device.tile_size||'normal')===s?' active':''}"
                data-size="${s}" title="${SIZE_LABELS[s]}" onclick="stageTileSize('${device.device_id}','${s}',event)">
          ${SIZE_LABELS[s]}
        </button>`).join('')}
    </div>

    <!-- drag handle + controls (top-right) -->
    <div class="tile-controls" onmousedown="event.stopPropagation()">
      <span class="tile-drag-handle" title="Drag to reorder">⠿</span>
      <button class="tile-remove-btn" title="Hide / remove"
              onclick="event.stopPropagation();openCtxMenu(event,'${device.device_id}')">✕</button>
    </div>

    <div class="device-card-head">
      <div>
        <div class="device-name">${escHtml(device.name)}</div>
        <div class="device-host">${escHtml(device.host || '')}</div>
      </div>
      <span class="device-type-badge">${escHtml(device.method || device.type || 'ping')}</span>
    </div>

    <div class="status-row">
      <span class="dot ${device.status} pulse"></span>
      <span class="status-label ${device.status}">${statusLabel(device.status)}</span>
    </div>

    <div class="metric-grid">${buildMetricsHTML(device)}</div>
    <div class="device-error" style="display:${device.last_error ? '' : 'none'}">${escHtml(device.last_error || '')}</div>
    <div class="device-foot">${buildFootHTML(device)}</div>

    <!-- V7.2: corner drag-resize handle -->
    <div class="tile-resize-handle" title="Drag to resize">
      <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="14" y1="0"  x2="0"  y2="14"/>
        <line x1="14" y1="5"  x2="5"  y2="14"/>
        <line x1="14" y1="10" x2="10" y2="14"/>
      </svg>
    </div>`;
}

function buildMetricsHTML(device) {
  const m = device.metrics || {};
  const pairs = [
    ['CPU',      m.cpu_pct     != null ? m.cpu_pct.toFixed(1) + '%' : null],
    ['Memory',   m.memory_pct  != null ? m.memory_pct.toFixed(1) + '%' : null],
    ['Disk',     m.disk_pct    != null ? m.disk_pct.toFixed(1) + '%' : null],
    ['Latency',  m.latency_ms  != null ? m.latency_ms.toFixed(1) + ' ms' : null],
    ['Loss',     m.packet_loss_pct != null ? m.packet_loss_pct.toFixed(1) + '%' : null],
    ['Uptime',   m.uptime_days != null ? m.uptime_days.toFixed(1) + 'd' : null],
    ['Free',     m.free_gb     != null ? m.free_gb.toFixed(1) + ' GB' : null],
    // V8.2 fix: url-method devices report these fields (see url_check.py)
    // but nothing here recognised them, so every Sites Monitor tile showed
    // "No metrics collected yet" forever even though the values were
    // already being recorded server-side.
    ['Response', m.response_ms   != null ? m.response_ms.toFixed(0) + ' ms' : null],
    ['HTTP',     m.status_code   != null ? String(m.status_code) : null],
    ['SSL exp.', m.ssl_days_left != null ? m.ssl_days_left + 'd' : null],
    ['Size',     m.content_size_kb != null ? m.content_size_kb.toFixed(1) + ' KB' : null],
  ].filter(([_, v]) => v !== null);

  // V8.2: per-service / per-task sub-checks attached to a host (see
  // service_check.py / task_check.py) report as metrics.services /
  // metrics.tasks arrays. Show a compact "N/M up" summary cell instead of
  // one row per item so a host watching many services doesn't blow up the
  // tile -- full detail is available in the device's expanded view.
  if (Array.isArray(m.services) && m.services.length) {
    const up = m.services.filter(s => s.running).length;
    pairs.push(['Services', `${up}/${m.services.length} up`]);
  }
  if (Array.isArray(m.tasks) && m.tasks.length) {
    const ok = m.tasks.filter(t => t.ok).length;
    pairs.push(['Tasks', `${ok}/${m.tasks.length} ok`]);
  }

  if (!pairs.length) return `<div class="metric-cell" style="grid-column:span 2;text-align:center;">
    <div class="metric-label" style="margin:0;">No metrics collected yet</div></div>`;
  return pairs.map(([k, v]) => `
    <div class="metric-cell">
      <div class="metric-value">${v === null ? '—' : escHtml(String(v))}</div>
      <div class="metric-label">${k}</div>
    </div>`).join('');
}

function buildFootHTML(device) {
  const ago = device.last_checked ? relativeTime(device.last_checked) : '—';
  return `<span>${escHtml(device.method || '')}</span><span>Checked ${ago}</span>`;
}

function relativeTime(ts) {
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 5)   return 'just now';
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// V8.2: display label only -- the underlying status value ("ok", "warning",
// "critical", "offline", "unknown") is unchanged and still drives the CSS
// class, so color rules / status filters elsewhere keep working untouched.
const STATUS_LABELS = { ok: 'Healthy', warning: 'Warning', critical: 'Critical', offline: 'Offline', unknown: 'Unknown' };
function statusLabel(status) {
  return STATUS_LABELS[status] || (status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Unknown');
}

function attachTileEvents(card, device) {
  const id = device.device_id;

  // V11.3 patch 04: double-click a tile = open that device's settings and thresholds
  card.addEventListener('dblclick', e => {
    if (typeof editMode !== 'undefined' && editMode) return;
    if (e.target.closest && e.target.closest('button, a, input, select, textarea')) return;
    try { window.getSelection().removeAllRanges(); } catch (_) {}
    openDeviceSettings(id);
  });

  // Drag-to-reorder (HTML5 drag API)
  card.addEventListener('dragstart', e => {
    dragSrcId = id;
    card.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', id);
  });
  card.addEventListener('dragend', () => {
    dragSrcId = null;
    card.classList.remove('dragging');
    document.querySelectorAll('.drag-over').forEach(c => c.classList.remove('drag-over'));
  });
  card.addEventListener('dragover', e => {
    if (!editMode) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragSrcId && dragSrcId !== id) card.classList.add('drag-over');
  });
  card.addEventListener('dragleave', () => card.classList.remove('drag-over'));
  card.addEventListener('drop', e => {
    e.preventDefault();
    card.classList.remove('drag-over');
    if (!editMode || !dragSrcId || dragSrcId === id) return;
    dropTile(dragSrcId, id);
  });

  // Right-click context menu (outside edit mode only)
  card.addEventListener('contextmenu', e => {
    if (editMode) return;
    e.preventDefault();
    openCtxMenu(e, id);
  });

  // Corner drag-resize handle
  const handle = card.querySelector('.tile-resize-handle');
  if (handle) {
    handle.addEventListener('mousedown', e => {
      if (!editMode) return;
      e.stopPropagation();
      e.preventDefault();
      const st = getTileState(id);
      resizeDev    = id;
      resizeStartX = e.clientX;
      resizeStartY = e.clientY;
      resizeOrigW  = SIZE_W[st.size] || st.grid_w || 1;
      resizeOrigH  = SIZE_H[st.size] || st.grid_h || 1;
      card.classList.add('resizing');
    });
  }
}

/* ================================================================
   Drag-to-reorder DOM manipulation
   ================================================================ */
function dropTile(srcId, targetId) {
  const grid  = document.getElementById('device-grid');
  const cards = grid ? [...grid.querySelectorAll('.device-card[data-id]')] : [];
  const src   = cards.find(c => c.dataset.id === srcId);
  const tgt   = cards.find(c => c.dataset.id === targetId);
  if (!src || !tgt) return;

  // Re-insert src before or after target based on visual position
  const srcIdx = cards.indexOf(src);
  const tgtIdx = cards.indexOf(tgt);
  if (srcIdx < tgtIdx) tgt.after(src);
  else tgt.before(src);

  // Update staged positions
  const newOrder = [...grid.querySelectorAll('.device-card[data-id]')];
  newOrder.forEach((c, i) => {
    const did = c.dataset.id;
    if (!stagedTiles[did]) stagedTiles[did] = { ...serverTiles[did] };
    stagedTiles[did].position = i;
  });
}

/* ================================================================
   Tile size presets (edit mode only)
   ================================================================ */
function stageTileSize(deviceId, size, event) {
  event.stopPropagation();
  if (!editMode) return;
  if (!stagedTiles[deviceId]) stagedTiles[deviceId] = { ...serverTiles[deviceId] };
  stagedTiles[deviceId].size   = size;
  stagedTiles[deviceId].grid_w = SIZE_W[size] || 1;
  stagedTiles[deviceId].grid_h = SIZE_H[size] || 1;

  const grid = document.getElementById('device-grid');
  const card = grid?.querySelector(`.device-card[data-id="${deviceId}"]`);
  if (card) {
    applyTileSpan(card, size, SIZE_W[size], SIZE_H[size]);
    card.querySelectorAll('.tile-size-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.size === size);
    });
  }
}

/* ================================================================
   Corner drag-resize handler
   ================================================================ */
function onResizeMove(e) {
  if (!resizeDev || !editMode) return;
  const dx = e.clientX - resizeStartX;
  const dy = e.clientY - resizeStartY;
  const newW = Math.max(1, Math.min(6, resizeOrigW + Math.round(dx / RESIZE_COL_PX)));
  const newH = Math.max(1, Math.min(6, resizeOrigH + Math.round(dy / RESIZE_COL_PX)));

  if (!stagedTiles[resizeDev]) stagedTiles[resizeDev] = { ...serverTiles[resizeDev] };
  stagedTiles[resizeDev].size   = 'custom';
  stagedTiles[resizeDev].grid_w = newW;
  stagedTiles[resizeDev].grid_h = newH;

  const grid = document.getElementById('device-grid');
  const card = grid?.querySelector(`.device-card[data-id="${resizeDev}"]`);
  if (card) {
    card.style.gridColumn = `span ${newW}`;
    card.style.gridRow    = `span ${newH}`;
    card.style.setProperty('--tile-w', newW.toString());
    card.style.setProperty('--tile-h', newH.toString());
    card.querySelectorAll('.tile-size-btn').forEach(b => b.classList.remove('active'));
  }
}

function onResizeEnd() {
  if (!resizeDev) return;
  const grid = document.getElementById('device-grid');
  const card = grid?.querySelector(`.device-card[data-id="${resizeDev}"]`);
  if (card) card.classList.remove('resizing');
  resizeDev = null;
}

/* ================================================================
   Tile hide / unhide (outside edit mode — immediate save to global)
   ================================================================ */
async function hideTile(deviceId) {
  await apiFetch(`/api/tiles/${deviceId}/hide`, { method: 'POST' });
  await refresh();
}

async function unHideTile(deviceId) {
  await apiFetch(`/api/tiles/${deviceId}/show`, { method: 'POST' });
  await refresh();
}

// In edit mode, toggle hidden on the staged tile without an API call
function stageToggleHide(deviceId) {
  if (!stagedTiles[deviceId]) stagedTiles[deviceId] = { ...serverTiles[deviceId] };
  stagedTiles[deviceId].hidden = !stagedTiles[deviceId].hidden;
  renderDevices(allDevices, true);
}

/* ================================================================
   Context menu (outside edit mode)
   ================================================================ */
function openCtxMenu(e, deviceId) {
  if (editMode) return;
  ctxDeviceId = deviceId;
  const menu = document.getElementById('tile-ctx-menu');
  if (!menu) return;
  const rm = document.getElementById('ctx-remove-from-view'); if (rm) rm.style.display = String(currentCategory).startsWith('cv:') ? '' : 'none';
  menu.style.display = '';
  menu.style.left    = Math.min(e.clientX, window.innerWidth  - 210) + 'px';
  menu.style.top     = Math.min(e.clientY, window.innerHeight - 260) + 'px';
  e.stopPropagation();
}

function closeCtxMenu() {
  const m = document.getElementById('tile-ctx-menu');
  if (m) m.style.display = 'none';
}

function menuHideTile()         { closeCtxMenu(); hideTile(ctxDeviceId); }
function menuResizeTile(size)   {
  closeCtxMenu();
  if (!ctxDeviceId) return;
  apiFetch(`/api/tiles/${ctxDeviceId}/size`, { method:'POST', body: JSON.stringify({ size }) });
  // Optimistic local update
  const grid = document.getElementById('device-grid');
  const card = grid?.querySelector(`.device-card[data-id="${ctxDeviceId}"]`);
  if (card) applyTileSpan(card, size, SIZE_W[size]||1, SIZE_H[size]||1);
  // Sync serverTiles
  if (serverTiles[ctxDeviceId]) serverTiles[ctxDeviceId].size = size;
}

async function menuRemoveDevice() {
  closeCtxMenu();
  if (!ctxDeviceId) return;
  if (!confirm(`Permanently remove "${ctxDeviceId}" and stop monitoring?`)) return;
  await apiFetch(`/api/devices/${ctxDeviceId}`, { method: 'DELETE' });
  await refresh();
}

/* ================================================================
   Quick-add tile modal — Existing Device (checkbox list) | New Device
   ================================================================ */
let qaExistingDirty = false;   // tracks unsaved checkbox changes

function openQuickAdd() {
  document.getElementById('quick-add-overlay')?.classList.remove('hidden');
  qaSwitchSource('existing');
  loadQaExistingList();
  buildQaFields();
}

function qaSwitchSource(which) {
  const tabExisting = document.getElementById('qa-tab-existing');
  const tabNew       = document.getElementById('qa-tab-new');
  const paneExisting = document.getElementById('qa-pane-existing');
  const paneNew       = document.getElementById('qa-pane-new');
  if (which === 'existing') {
    tabExisting.classList.add('active');
    tabNew.classList.remove('active');
    paneExisting.style.display = '';
    paneNew.style.display = 'none';
  } else {
    tabExisting.classList.remove('active');
    tabNew.classList.add('active');
    paneExisting.style.display = 'none';
    paneNew.style.display = 'flex';
  }
}

async function loadQaExistingList() {
  const listEl = document.getElementById('qa-existing-list');
  if (!listEl) return;
  listEl.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px 0;">Loading devices...</div>';
  try {
    const res  = await apiFetch('/api/status');
    const data = await res.json();
    const devices = data.devices || [];
    if (!devices.length) {
      listEl.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px 0;">' +
        'No devices exist yet. Switch to "New Device" to create one.</div>';
      return;
    }
    window._qaAllDevices = devices;
    renderQaExistingList(devices);
  } catch (e) {
    listEl.innerHTML = `<div style="color:var(--status-critical);font-size:13px;">Failed to load: ${e.message}</div>`;
  }
}

function renderQaExistingList(devices) {
  const listEl = document.getElementById('qa-existing-list');
  if (!listEl) return;
  if (!devices.length) {
    listEl.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px 0;">No devices match your filter.</div>';
    return;
  }

  const CAT_LABELS = { network:'Network Devices', firewall:'Firewalls', windows:'Windows Devices',
                        linux:'Linux Devices', url:'Sites' };
  const groups = {};
  devices.forEach(d => {
    const c = _deviceCategory(d);
    (groups[c] = groups[c] || []).push(d);
  });
  const order = ['network','firewall','windows','linux','url'];

  listEl.innerHTML = order.filter(c => groups[c] && groups[c].length).map(cat => {
    const rows = groups[cat].map(d => {
      const checked   = !d.tile_hidden ? 'checked' : '';
      const typeLabel = (d.method || d.type || '').toUpperCase();
      return `<label class="qa-existing-row">
        <input type="checkbox" data-device-id="${d.device_id}" ${checked}
               onchange="qaExistingDirty=true">
        <span style="font-weight:600;font-size:13px;">${d.name}</span>
        <span class="qa-existing-meta">${typeLabel} &middot; ${d.host || ''}</span>
      </label>`;
    }).join('');
    return `<div class="qa-cat-group">
      <div class="qa-cat-group-hdr">${CAT_LABELS[cat] || cat} <span class="qa-cat-count">${groups[cat].length}</span></div>
      ${rows}
    </div>`;
  }).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('qa-close')?.addEventListener('click',  () => closeQuickAdd());
  document.getElementById('qa-cancel')?.addEventListener('click', () => closeQuickAdd());
  document.getElementById('qa-submit')?.addEventListener('click', submitQuickAdd);
  document.getElementById('qa-kind')?.addEventListener('change', buildQaFields);
  document.getElementById('qa-existing-apply')?.addEventListener('click', applyQaExisting);
  document.getElementById('qa-existing-filter')?.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    const all = window._qaAllDevices || [];
    renderQaExistingList(all.filter(d =>
      d.name.toLowerCase().includes(q) || (d.host || '').toLowerCase().includes(q)
    ));
  });
});

async function applyQaExisting() {
  const rows = document.querySelectorAll('#qa-existing-list input[type=checkbox]');
  const showIds = [];
  const hideIds = [];
  rows.forEach(cb => {
    const id = cb.dataset.deviceId;
    if (cb.checked) showIds.push(id); else hideIds.push(id);
  });
  try {
    await Promise.all([
      ...showIds.map(id => apiFetch(`/api/tiles/${id}/show`, { method: 'POST' })),
      ...hideIds.map(id => apiFetch(`/api/tiles/${id}/hide`, { method: 'POST' })),
    ]);
    showToast(`Dashboard updated — ${showIds.length} tile(s) visible`, 'success');
    closeQuickAdd();
    await refresh();
  } catch (e) {
    showToast('Failed to update tiles: ' + e.message, 'error');
  }
}

function closeQuickAdd() {
  document.getElementById('quick-add-overlay')?.classList.add('hidden');
}
function buildQaFields() {
  const kind = document.getElementById('qa-kind')?.value || 'server_ping';
  const cf   = document.getElementById('qa-cred-fields');
  const pf   = document.getElementById('qa-path-field');
  const mf   = document.getElementById('qa-metric-fields');
  if (!cf) return;
  const needsCreds   = kind.includes('windows') || kind.includes('ssh');
  const isDrive      = kind.includes('drive');
  if (pf) pf.style.display = isDrive ? '' : 'none';
  cf.innerHTML = needsCreds ? `
    <div class="form-grid">
      <div class="field"><label>Username</label>
        <input id="qa-user" type="text" placeholder="domain\\user or user"></div>
      <div class="field"><label>Password</label>
        <input id="qa-pass" type="password" placeholder="password"></div>
    </div>
    ${kind.includes('windows') ? `<div class="field">
      <label>Remote (WinRM)?</label>
      <select id="qa-remote"><option value="1">Yes</option><option value="0">No</option></select>
    </div>` : ''}` : '';
  if (mf) mf.innerHTML = kind === 'url' ? `
    <div class="field" style="border-top:1px solid var(--border);padding-top:10px;margin-top:2px;">
      <label style="font-size:12px;color:var(--text-muted);">URL monitoring options</label>
      <div class="form-grid" style="margin-top:6px;">
        <div class="field"><label>Expected HTTP status</label>
          <input id="qa-url-status" type="number" value="200" min="100" max="599"></div>
        <div class="field" style="justify-content:flex-end;">
          <label style="display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer;">
            <input type="checkbox" id="qa-url-ssl" checked> Verify SSL certificate</label>
        </div>
      </div>
    </div>` : `
    <div class="field" style="border-top:1px solid var(--border);padding-top:10px;margin-top:2px;">
      <label style="font-size:12px;color:var(--text-muted);">Monitoring options</label>
      <div style="display:flex;flex-direction:column;gap:6px;margin-top:6px;">
        ${kind.includes('windows') || kind.includes('ssh') ? `
          <label style="display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer;">
            <input type="checkbox" id="qa-m-cpu" checked> CPU usage</label>
          <label style="display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer;">
            <input type="checkbox" id="qa-m-mem" checked> Memory usage</label>
          <label style="display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer;">
            <input type="checkbox" id="qa-m-disk" checked> Disk usage</label>` : ''}
        <label style="display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer;">
          <input type="checkbox" id="qa-m-ping" checked> Ping / latency</label>
      </div>
    </div>`;
}
async function submitQuickAdd() {
  const id   = document.getElementById('qa-id')?.value.trim();
  const name = document.getElementById('qa-name')?.value.trim();
  const host = document.getElementById('qa-host')?.value.trim();
  const kind = document.getElementById('qa-kind')?.value || 'server_ping';
  if (!id || !name || !host) { showToast('ID, Name and Host are required.', 'error'); return; }
  // V8.2 fix: 'url' (the "Web application URL" option in #qa-kind) had no
  // entry here, so methodMap[kind] was undefined and every URL added from
  // this dashboard quick-add fell back to method:'ping' -- landing it on
  // the Network tab instead of URL. type must also match what the Sites
  // Monitor page itself uses (type:'web') for consistent categorization.
  const methodMap = {
    server_ping:'ping', server_windows:'powershell', server_ssh:'ssh',
    shared_drive_windows:'disk_usage', shared_drive_linux:'disk_usage',
    url:'url'
  };
  const body = {
    id, name, host,
    type:   kind === 'url' ? 'web' : (kind.includes('drive') ? 'storage' : 'server'),
    method: methodMap[kind] || 'ping',
  };
  if (document.getElementById('qa-user')?.value) {
    body.username = document.getElementById('qa-user').value;
    body.password = document.getElementById('qa-pass')?.value || '';
  }
  if (document.getElementById('qa-remote')) body.remote = document.getElementById('qa-remote').value === '1';
  if (document.getElementById('qa-path'))  body.path   = document.getElementById('qa-path').value;
  if (kind === 'url') {
    body.url_config = {
      expected_status: parseInt(document.getElementById('qa-url-status')?.value, 10) || 200,
      check_ssl:        document.getElementById('qa-url-ssl')?.checked !== false,
      timeout_sec:      10,
    };
  }

  const btn = document.getElementById('qa-submit');
  if (btn) btn.disabled = true;
  try {
    const res = await apiFetch('/api/devices', { method: 'POST', body: JSON.stringify(body) });
    if (!res.ok) { const d = await res.json(); throw new Error(d.error || 'HTTP ' + res.status); }
    showToast(`"${name}" added and monitoring started.`, 'success');
    closeQuickAdd();
    // Force layout re-fetch so new device appears without manual sign-out
    await refresh();
    // Also poll again after scheduler picks up the new device (2 sec delay)
    setTimeout(async () => { await refresh(); }, 2500);
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ═══════════════════════════════════════════════════════════
   V11.3 patch 04 -- device window: double-click a tile
   Shows what the device is, how it is checked, its live status and the thresholds that apply to it (with the layer each
   value comes from) and lets an administrator set this device's own values. The full edit / notification screens are
   one click away.
   ═══════════════════════════════════════════════════════════ */
const DS_IDS = { en: 'ds-en-', w: 'ds-w-', c: 'ds-c-', wait: 'ds-wait-' };
let _dsDevice = null, _dsKeys = [];

function dsEsc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

function closeDeviceSettings() {
  const m = document.getElementById('ds-modal'); if (m) m.classList.add('hidden');
  _dsDevice = null;
}

async function openDeviceSettings(deviceId) {
  const modal = document.getElementById('ds-modal'), body = document.getElementById('ds-body');
  if (!modal || !body) return;
  _dsDevice = deviceId;
  document.getElementById('ds-title').textContent = 'Device settings';
  document.getElementById('ds-sub').textContent = '';
  body.innerHTML = '<div style="color:var(--text-muted)">Loading\u2026</div>';
  modal.classList.remove('hidden');
  try {
    const [meta, r] = await Promise.all([ThrUI.load(), fetch('/api/devices/' + encodeURIComponent(deviceId) + '/thresholds', { headers: { 'X-Session-Token': getSession() } })]);
    if (r.status === 401 || r.status === 403) { body.innerHTML = '<p>Sign in as an <strong>administrator</strong> to view and change device settings.</p>'; return; }
    if (!r.ok) { body.innerHTML = '<p style="color:var(--status-critical)">Could not load this device (' + r.status + ').</p>'; return; }
    renderDeviceSettings(meta, await r.json());
  } catch (e) {
    body.innerHTML = '<p style="color:var(--status-critical)">Could not load this device: ' + dsEsc(e.message) + '</p>';
  }
}

function renderDeviceSettings(meta, data) {
  const d = data.device, n = data.notify || {}, body = document.getElementById('ds-body');
  document.getElementById('ds-title').textContent = d.name;
  document.getElementById('ds-sub').innerHTML = dsEsc(d.type_label || 'Device') + ' &middot; ' + dsEsc(d.method_label || d.method) + ' &middot; ' + dsEsc(d.host || '');
  _dsKeys = data.metrics.map(m => m.key);
  const saved = {}, inherit = {}, sources = {};
  data.metrics.forEach(m => { if (Object.keys(m.override || {}).length) saved[m.key] = m.override; inherit[m.key] = m.effective; sources[m.key] = m.source; });
  const since = d.last_checked ? new Date(d.last_checked * 1000).toLocaleString() : 'not checked yet';
  const trig = n.alert_trigger_mode === 'immediate' ? 'alert immediately' : 'wait ' + (n.escalation_after_sec_l1 || 60) + ' s to confirm';
  const rep = n.alert_notify_mode === 'cooldown' ? 'repeats at least ' + (n.notify_cooldown_sec || 300) + ' s apart' : 'repeats immediately';
  const id = encodeURIComponent(d.id);
  const table = ThrUI.tableHTML(meta, _dsKeys, saved, DS_IDS, { wait: true, waitPlaceholder: n.escalation_after_sec_l1 || 60, inherit, sources });
  body.innerHTML =
    '<div class="ds-grid">' +
      '<div><span class="ds-k">Status</span><span class="status-label ' + dsEsc(d.status) + '">' + dsEsc(typeof statusLabel === 'function' ? statusLabel(d.status) : d.status) + '</span></div>' +
      '<div><span class="ds-k">Last check</span>' + dsEsc(since) + '</div>' +
      '<div><span class="ds-k">Checks every</span>' + dsEsc(d.poll_interval_seconds || 30) + ' s</div>' +
      '<div><span class="ds-k">Alerts</span>' + dsEsc(n.notifications_enabled === 0 ? 'off' : trig + '; ' + rep) + '</div>' +
    '</div>' +
    (d.last_error ? '<div class="ds-err">' + dsEsc(d.last_error) + '</div>' : '') +
    '<h3 style="margin:14px 0 4px;font-size:14px">Thresholds for this device</h3>' +
    '<p class="ds-note">Grey numbers are what applies now and <strong>Comes from</strong> says where they are set. Type a value to give <strong>this device</strong> its own; leave a box empty to inherit. Hover or click the <span class="thr-i" style="pointer-events:none">!</span> for details.</p>' +
    '<div style="overflow-x:auto">' + table + '</div>' +
    '<div class="ds-actions">' +
      '<button type="button" class="btn primary" onclick="saveDeviceSettings(false)" title="Save and keep this window open">Save</button>' +
      '<button type="button" class="btn primary" onclick="saveDeviceSettings(true)" title="Save and close this window">Save &amp; close</button>' +
      '<button type="button" class="btn secondary" onclick="closeDeviceSettings()" title="Close without saving">Cancel</button>' +
      '<button type="button" class="btn secondary small" onclick="resetDeviceSettings()" title="Empty every box so this device follows the inherited values (then press Save)">Use inherited values</button>' +
      '<span id="ds-status" class="ds-status"></span>' +
    '</div>' +
    '<div class="apply-timing" id="ds-apply-thr"></div>' +
    '<div class="ds-links">' +
      '<a class="btn secondary small" href="/devices#edit=' + id + '">Edit device settings</a> ' +
      '<a class="btn secondary small" href="/devices#notify=' + id + '">Notifications &amp; escalation</a>' +
    '</div>';
  dsRenderBar(d.id);
}

// V11.3 patch 06: "apply these thresholds to ..." -- this device / same type / same method / all devices (or sites) /
// the tiles currently shown on the dashboard (your active category tab and severity filter).
let _dsTargets = [];
async function dsRenderBar(deviceId) {
  const hb = document.getElementById('ds-apply-thr'); if (!hb) return;
  let ctx; try { ThrUI.resetContext(); ctx = await ThrUI.context(deviceId); } catch (e) { return; }
  if (deviceId !== _dsDevice) return;
  const shown = [...document.querySelectorAll('.device-card[data-id]')].filter(c => c.offsetParent !== null).map(c => c.getAttribute('data-id'));
  const total = (ctx.facets.methods || []).reduce((n, x) => n + (x.count || 0), 0);
  _dsTargets = ThrUI.targets(ctx.dev, ctx.facets, (shown.length > 1 && shown.length < total) ? shown : null, { methods: ctx.methodOf });
  const f = _dsTargets.find(t => t.key === 'filter'); if (f) f.label = 'Tiles shown now';
  hb.innerHTML = ThrUI.barHTML('Apply the thresholds above to:', _dsTargets, 'dsApplyThr');
}
async function dsApplyThr(key) {
  const t = _dsTargets.find(x => x.key === key), meta = ThrUI.get(); if (!t || !meta || !_dsDevice) return;
  const { thresholds, errors } = ThrUI.collect(meta, _dsKeys, DS_IDS, { wait: true });
  if (errors.length) { dsStatus(errors[0], false); return; }
  try {
    const res = await ThrUI.applyThr(t, thresholds); if (res.cancelled) return;
    dsStatus(res.message, !!res.ok);
    if (res.ok) openDeviceSettings(_dsDevice).then(() => dsStatus(res.message, true));
  } catch (e) { dsStatus('Apply failed: ' + e.message, false); }
}

function dsStatus(msg, ok) { const e = document.getElementById('ds-status'); if (e) { e.textContent = msg; e.style.color = ok ? 'var(--status-ok)' : 'var(--status-critical)'; } }

async function saveDeviceSettings(closeAfter) {
  const meta = ThrUI.get(); if (!meta || !_dsDevice) return;
  const { thresholds, errors } = ThrUI.collect(meta, _dsKeys, DS_IDS, { wait: true });
  if (errors.length) { dsStatus(errors[0], false); return; }
  const r = await fetch('/api/devices/' + encodeURIComponent(_dsDevice) + '/thresholds', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ thresholds: ThrUI.compact(thresholds) }) });
  let j = {}; try { j = await r.json(); } catch (_) {}
  if (!r.ok || !j.ok) { dsStatus((j && j.error) || ('Save failed (' + r.status + ')'), false); return; }
  if (closeAfter) { closeDeviceSettings(); showToast('Saved \u2713', 'success'); return; }
  dsStatus('Saved \u2713 (' + j.overrides + ' own value' + (j.overrides === 1 ? '' : 's') + ') \u2014 applies from the next check', true);
  openDeviceSettings(_dsDevice).then(() => dsStatus('Saved \u2713 \u2014 applies from the next check', true));
}

function resetDeviceSettings() {
  _dsKeys.forEach(k => {
    ['w', 'c', 'wait'].forEach(p => { const el = document.getElementById(DS_IDS[p] + k); if (el) el.value = ''; });
    const en = document.getElementById(DS_IDS.en + k); if (en) en.checked = true;
  });
  dsStatus('All boxes cleared \u2014 click Save thresholds to use the inherited values', true);
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') { const m = document.getElementById('ds-modal'); if (m && !m.classList.contains('hidden')) closeDeviceSettings(); } });
document.addEventListener('click', e => { const m = document.getElementById('ds-modal'); if (m && e.target === m) closeDeviceSettings(); });
