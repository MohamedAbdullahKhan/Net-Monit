/* =============================================================================
 * Net-monit V11.3
 * Copyright (c) 2024-2026 Abdullah. All rights reserved.
 * Contact: abuabdullah.be@outlook.com
 * ============================================================================= */
/* settings.js — V3.5 (FIXED)
 * FIXES:
 *  • saveEscGlobal / saveGlobalThresh / saveNotif — 404 bug fixed (routes reordered in app.py)
 *  • Escalation: toggle per-level (disabled by default); choose receivers per level
 *  • Devices quick-add: credential fields per method
 *  • Thresholds save/reset now works
 *  • Audit tab split: User/Device Audit + Alert Log
 *  • Dashboard tile manual refresh button (via /api/status?device=id)
 * ============================================================================= */
"use strict";

const parseEmails = t => t.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
// V8.5: same split/trim rule as parseEmails, named separately for phone
// numbers so intent is clear at each call site (mirrors devices.js's
// identically-named, identically-implemented helper -- each JS file in
// this codebase is self-contained, no shared module to import from).
const phoneListToArr = t => t.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
const fmtEmails   = a => (a||[]).join("\n");
const esc = s => String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
const timeAgo = ts => {
  if(!ts) return "never";
  const d = Math.max(0, Date.now()/1000-ts);
  if(d<60)    return `${Math.floor(d)}s ago`;
  if(d<3600)  return `${Math.floor(d/60)}m ago`;
  if(d<86400) return `${Math.floor(d/3600)}h ago`;
  return `${Math.floor(d/86400)}d ago`;
};
const v = id => document.getElementById(id);
const setStatus = (id, msg, ok) => {
  const el = v(id); if(!el) return;
  el.textContent = msg;
  el.style.color = ok ? "var(--status-ok)" : "var(--status-critical)";
  setTimeout(()=>{ el.textContent=""; }, 5000);
};

// V11.1: the metric list, labels, units, ranges, recommended values and which metrics each monitoring method
// (including "url" = websites) offers now come from the server (monitor/threshold_meta.py via
// /api/threshold-meta) and are rendered by static/js/threshold_ui.js (ThrUI). The old hard-coded copies of the
// six DEVICE metrics lived here, had no entry for sites, and made a website show CPU/Memory/Disk.

let _allKnownEmails = [];

// ── Access gate ───────────────────────────────────────────────────────────
function checkAccess(){
  const role = sessionStorage.getItem("netmon_role");
  const sess = getSession();
  const isAdm = role==="admin" && !!sess;
  v("settings-locked")  && (v("settings-locked").style.display  = isAdm ? "none" : "");
  v("settings-content") && (v("settings-content").style.display = isAdm ? "" : "none");
  if(isAdm) initAll();
}
function onAdminLogin()  { checkAccess(); }
function onAdminLogout() { checkAccess(); }

// ── Tab switching ─────────────────────────────────────────────────────────
function switchTab(name){
  document.querySelectorAll(".stab").forEach(b=>b.classList.toggle("active",b.dataset.tab===name));
  document.querySelectorAll(".stab-panel").forEach(p=>p.classList.toggle("active",p.id==="tab-"+name));
  TAB_LOADERS[name] && TAB_LOADERS[name]();
}
const TAB_LOADERS = {
  email:loadSmtp, notifications:loadNotifTab, escalation:loadEscTab,
  templates:loadNotificationTemplatesTab,
  thresholds:loadThreshTab, devices:loadDevicesTab, users:loadUsersTab,
  audit:loadAuditTab, alerts:loadAlerts,
  smscall:loadSmsCallTab, organisation:loadOrganisationTab,
};

/* ═══════════════════════════════════════════════════════════
   SMTP
═══════════════════════════════════════════════════════════ */
async function loadSmtp(){
  try{
    const r=await fetch("/api/settings/smtp",{headers:{"X-Session-Token":getSession()}});
    if(!r.ok) return;
    const s=await r.json();
    ["s-enabled","s-host","s-port","s-tls","s-username","s-from","s-resend"].forEach(id=>{
      const key=id.replace("s-","").replace(/-/g,"_");
      const map={"s-enabled":"enabled","s-host":"host","s-port":"port","s-tls":"use_tls","s-username":"username","s-from":"from_address","s-resend":"resend_interval_minutes"};
      if(v(id) && s[map[id]]!=null) v(id).value = String(s[map[id]]);
    });
    v("s-admin-emails")   && (v("s-admin-emails").value   = fmtEmails(s.admin_emails||s.to_addresses||[]));
    v("s-support-emails") && (v("s-support-emails").value = fmtEmails(s.support_emails||[]));
    v("s-manager-emails") && (v("s-manager-emails").value = fmtEmails(s.manager_emails||[]));
  }catch(e){ console.error("loadSmtp",e); }
}
async function saveSmtp(){
  const payload={
    enabled:v("s-enabled")?.value==="true",
    host:v("s-host")?.value.trim()||"",
    port:parseInt(v("s-port")?.value||"587"),
    use_tls:v("s-tls")?.value!=="false",
    username:v("s-username")?.value.trim()||"",
    from_address:v("s-from")?.value.trim()||"",
    resend_interval_minutes:parseInt(v("s-resend")?.value||"30"),
    admin_emails:parseEmails(v("s-admin-emails")?.value||""),
    support_emails:parseEmails(v("s-support-emails")?.value||""),
    manager_emails:parseEmails(v("s-manager-emails")?.value||""),
  };
  payload.to_addresses=payload.admin_emails;
  const pw=v("s-password")?.value; if(pw) payload.password=pw;
  const r=await fetch("/api/settings/smtp",{method:"POST",headers:authHeaders(),body:JSON.stringify(payload)});
  setStatus("s-smtp-status",r.ok?"Saved ✓":"Save failed — check server log",r.ok);
  if(r.ok && v("s-password")) v("s-password").value="";
}
async function testEmail(state){
  const r=await fetch("/api/settings/test-email",{method:"POST",headers:authHeaders(),body:JSON.stringify({state})});
  const d=await r.json();
  showToast(d.ok?`Test ${state} email sent ✓`:`Failed: ${d.message}`,d.ok?"success":"error");
}

/* ═══════════════════════════════════════════════════════════
   NOTIFICATIONS
═══════════════════════════════════════════════════════════ */
async function loadNotifTab(){
  try{
    const r=await fetch("/api/settings/notifications",{headers:{"X-Session-Token":getSession()}});
    if(r.ok){
      const s=await r.json();
      v("n-send-warn")    && (v("n-send-warn").value    = String(s.send_on_warning   !==false));
      v("n-send-crit")    && (v("n-send-crit").value    = String(s.send_on_critical  !==false));
      v("n-send-recov")   && (v("n-send-recov").value   = String(s.send_on_recovery  !==false));
      v("n-send-offline") && (v("n-send-offline").value = String(s.send_on_offline   !==false));
      v("n-resend-warn")  && (v("n-resend-warn").value  = s.resend_warn_minutes||60);
      v("n-resend-crit")  && (v("n-resend-crit").value  = s.resend_crit_minutes||30);
    }
  }catch(e){}
  loadNotifDeviceTable();
}
async function saveNotif(){
  const payload={
    send_on_warning: v("n-send-warn")?.value!=="false",
    send_on_critical:v("n-send-crit")?.value!=="false",
    send_on_recovery:v("n-send-recov")?.value!=="false",
    send_on_offline: v("n-send-offline")?.value!=="false",
    resend_warn_minutes:parseInt(v("n-resend-warn")?.value||60),
    resend_crit_minutes:parseInt(v("n-resend-crit")?.value||30),
  };
  const r=await fetch("/api/settings/notifications",{method:"POST",headers:authHeaders(),body:JSON.stringify(payload)});
  setStatus("s-notif-status",r.ok?"Saved ✓":"Save failed — check server log",r.ok);
}
async function loadNotifDeviceTable(){
  try{
    const devR=await fetch("/api/devices",{headers:{"X-Session-Token":getSession()}});
    const devices=await devR.json();
    const tbody=v("notif-device-tbody"); if(!tbody) return;
    const notifMap=await getNotifyMap(devices);
    tbody.innerHTML=devices.map(d=>{
      const n=notifMap[d.id]||{};
      const en=n.notifications_enabled!==0;
      const emails=(n.notify_emails||[]).length?n.notify_emails.slice(0,2).join(", ")+(n.notify_emails.length>2?` +${n.notify_emails.length-2}…`:""):"<span style='color:var(--text-muted)'>admin (default)</span>";
      return `<tr ${MonFilter.attrs(d)}>
        <td><strong>${esc(d.name)}</strong>${MonFilter.sub(d)}</td>
        <td><span style="color:${en?"var(--status-ok)":"var(--text-muted)"}">${en?"● Enabled":"○ Disabled"}</span></td>
        <td style="font-size:12px">${emails}</td>
        <td><button class="btn secondary small" onclick="openSettNotify('${esc(d.id)}','${esc(d.name)}')">Edit</button></td>
      </tr>`;
    }).join("")||`<tr><td colspan="4" style="color:var(--text-muted);text-align:center;padding:16px">No devices</td></tr>`;
    MonFilter.mount("mf-notif","tab-notifications");
  }catch(e){}
}

/* ═══════════════════════════════════════════════════════════
   ESCALATION  (FIXED: toggle per level, default=disabled)
═══════════════════════════════════════════════════════════ */
// State object for the 3 toggle levels
const ESC_GLOBAL = { l1:false, l2:false, l3:false };

async function loadEscTab(){
  loadOfflineDetection();
  try{
    const gr=await fetch("/api/admin/email-groups",{headers:{"X-Session-Token":getSession()}});
    if(gr.ok){ const g=await gr.json(); _allKnownEmails=g.all_emails||[]; }
  }catch(_){}
  try{
    const r=await fetch("/api/settings/escalation-defaults",{headers:{"X-Session-Token":getSession()}});
    if(r.ok){
      const s=await r.json();
      // Check if any emails exist to decide toggle state
      ESC_GLOBAL.l1 = (s.escalation_emails_l1||[]).length>0 || (s.escalation_after_sec_l1>0 && s._l1_enabled===true);
      ESC_GLOBAL.l2 = (s.escalation_emails_l2||[]).length>0;
      ESC_GLOBAL.l3 = (s.escalation_emails_l3||[]).length>0;
      window._escGlobalData = s;
      const tmSel = v("esc-g-trigger-mode");
      if (tmSel) tmSel.value = s.alert_trigger_mode || "sustained";
      const nmSel = v("esc-g-notify-mode");
      if (nmSel) nmSel.value = s.alert_notify_mode || "immediate";
      const cdSec = v("esc-g-cooldown-sec");
      if (cdSec) cdSec.value = s.notify_cooldown_sec || 300;
    }
  }catch(e){}
  renderEscGlobalUI();
  loadEscDeviceTable();
  // V8.2: initialize the inline "wait ___ seconds" field alongside the
  // trigger-mode dropdown, from the same value the Level 1 card just
  // rendered with, and show/hide it based on the loaded mode.
  const waitField = v("esc-g-wait-sec");
  if (waitField) waitField.value = (window._escGlobalData||{}).escalation_after_sec_l1 || 60;
  toggleEscGWaitField();
  toggleEscGCooldownField();
}

function toggleEscGWaitField(){
  const mode  = v("esc-g-trigger-mode")?.value;
  const field = v("esc-g-wait-field");
  if (field) field.style.display = mode === "sustained" ? "flex" : "none";
}
// V8.4: mirrors toggleEscGWaitField's show/hide pattern for the new
// cooldown seconds input.
function toggleEscGCooldownField(){
  const mode  = v("esc-g-notify-mode")?.value;
  const field = v("esc-g-cooldown-field");
  if (field) field.style.display = mode === "cooldown" ? "flex" : "none";
}
function syncEscGWaitToL1(){
  // The inline field is the primary place to edit this once "Wait to
  // confirm" is selected -- push it straight into the Level 1 seconds
  // field so there's a single source of truth at save time.
  const waitVal = v("esc-g-wait-sec")?.value;
  const l1 = v("esc-g-sec-l1");
  if (l1 && waitVal) l1.value = waitVal;
}
function syncL1ToEscGWait(){
  // ...and the reverse: editing Level 1 directly in the card below also
  // keeps the inline field showing the same number.
  const l1 = v("esc-g-sec-l1")?.value;
  const waitField = v("esc-g-wait-sec");
  if (waitField && l1) waitField.value = l1;
}

function renderEscGlobalUI(){
  const c=v("esc-levels-container"); if(!c) return;
  const s=window._escGlobalData||{};
  const defs=[
    {n:1,key:"l1",col:"#F2B84B",sec:s.escalation_after_sec_l1||60,emails:s.escalation_emails_l1||[]},
    {n:2,key:"l2",col:"#FF8C00",sec:s.escalation_after_sec_l2||600,emails:s.escalation_emails_l2||[]},
    {n:3,key:"l3",col:"#FF5C5C",sec:s.escalation_after_sec_l3||1200,emails:s.escalation_emails_l3||[]},
  ];
  c.innerHTML=defs.map(lv=>{
    const on=ESC_GLOBAL[lv.key];
    return `<div style="border:1px solid ${on?lv.col+"44":"var(--border)"};border-radius:var(--radius-sm);
      padding:12px 14px;margin-bottom:10px;border-left:3px solid ${on?lv.col:"var(--border)"};
      transition:border .2s;opacity:${on?1:.6}">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
        <label class="toggle-wrap" style="cursor:pointer;display:flex;align-items:center;gap:8px;">
          <span class="toggle-sw ${on?"on":""}" id="esc-tog-l${lv.n}" onclick="toggleEscLevel(${lv.n})"></span>
          <span style="font-size:13px;font-weight:700;color:${on?lv.col:"var(--text-muted)"};">⚡ Level ${lv.n}</span>
        </label>
        <div style="display:flex;align-items:center;gap:6px;${on?"":"opacity:.4;pointer-events:none"}">
          <label style="font-size:12px;color:var(--text-muted)">Escalate after</label>
          <input id="esc-g-sec-l${lv.n}" type="number" style="width:75px" value="${lv.sec}" min="30"
            ${lv.n===1?'onchange="syncL1ToEscGWait()"':''}>
          <span style="font-size:12px;color:var(--text-muted)">seconds</span>
        </div>
      </div>
      <div style="${on?"":"opacity:.4;pointer-events:none"};margin-top:10px;">
        <label style="font-size:12px;color:var(--text-secondary)">Level ${lv.n} escalation emails</label>
        <textarea id="esc-g-emails-l${lv.n}" rows="2" class="code-textarea" style="margin-top:4px"
          placeholder="Enter email addresses (one per line)">${fmtEmails(lv.emails)}</textarea>
        ${_renderEmailPickerInline("esc-g-emails-l"+lv.n,lv.emails)}
      </div>
    </div>`;
  }).join("");
}

function toggleEscLevel(n){
  const key="l"+n;
  ESC_GLOBAL[key]=!ESC_GLOBAL[key];
  renderEscGlobalUI();
}

function _renderEmailPickerInline(taId, current){
  if(!_allKnownEmails.length) return "";
  return `<div style="margin-top:5px;display:flex;flex-wrap:wrap;gap:4px;">
    ${_allKnownEmails.map(e=>`
      <label style="display:flex;align-items:center;gap:3px;font-size:11.5px;cursor:pointer;
        padding:2px 8px;border-radius:4px;border:1px solid var(--border);background:var(--bg-hover);
        ${(current||[]).includes(e)?"border-color:var(--accent);background:rgba(79,209,197,.08)":""}">
        <input type="checkbox" data-email="${esc(e)}" data-target="${taId}"
          ${(current||[]).includes(e)?"checked":""}
          onchange="_syncEmailCb(this)"> ${esc(e)}</label>`).join("")}
  </div>`;
}

function _syncEmailCb(cb){
  const ta=document.getElementById(cb.dataset.target); if(!ta) return;
  const emails=ta.value.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
  const email=cb.dataset.email;
  if(cb.checked){if(!emails.includes(email))emails.push(email);}
  else{const i=emails.indexOf(email);if(i>=0)emails.splice(i,1);}
  ta.value=emails.join("\n");
  // sync sibling checkboxes
  document.querySelectorAll(`input[type=checkbox][data-target="${cb.dataset.target}"][data-email="${email}"]`)
    .forEach(o=>{if(o!==cb)o.checked=cb.checked;});
}

async function saveEscGlobal(){
  if (v("esc-g-trigger-mode")?.value === "sustained") syncEscGWaitToL1();
  const getE=n=>{const t=v(`esc-g-emails-l${n}`);return t&&ESC_GLOBAL["l"+n]?parseEmails(t.value):[];};
  const getS=n=>{const t=v(`esc-g-sec-l${n}`);return t?parseInt(t.value)||60:60;};
  const payload={
    escalation_after_sec_l1:getS(1),
    escalation_after_sec_l2:getS(2),
    escalation_after_sec_l3:getS(3),
    escalation_emails_l1:getE(1),
    escalation_emails_l2:getE(2),
    escalation_emails_l3:getE(3),
    alert_trigger_mode:(v("esc-g-trigger-mode")?.value)||"sustained",
    alert_notify_mode:(v("esc-g-notify-mode")?.value)||"immediate",
    notify_cooldown_sec:parseInt(v("esc-g-cooldown-sec")?.value)||300,
    _l1_enabled:ESC_GLOBAL.l1,
    _l2_enabled:ESC_GLOBAL.l2,
    _l3_enabled:ESC_GLOBAL.l3,
  };
  const r=await fetch("/api/settings/escalation-defaults",{method:"POST",headers:authHeaders(),body:JSON.stringify(payload)});
  if(!r.ok){
    const txt=await r.text();
    setStatus("s-esc-status",`Save failed (${r.status}) — ${txt.substring(0,120)}`,false);
    return;
  }
  setStatus("s-esc-status","Saved ✓",true);
  window._escGlobalData=payload;
}

async function applyEscToAll(){
  if(!confirm("Apply current global escalation settings to ALL devices?")) return;
  const getE=n=>{const t=v(`esc-g-emails-l${n}`);return t&&ESC_GLOBAL["l"+n]?parseEmails(t.value):[];};
  const getS=n=>{const t=v(`esc-g-sec-l${n}`);return t?parseInt(t.value)||60:60;};
  const payload={
    escalation_after_sec_l1:getS(1),escalation_after_sec_l2:getS(2),escalation_after_sec_l3:getS(3),
    escalation_emails_l1:getE(1),escalation_emails_l2:getE(2),escalation_emails_l3:getE(3),
    escalation_levels:ESC_GLOBAL.l3?3:ESC_GLOBAL.l2?2:ESC_GLOBAL.l1?1:0,
    alert_trigger_mode:(v("esc-g-trigger-mode")?.value)||"sustained",
    alert_notify_mode:(v("esc-g-notify-mode")?.value)||"immediate",
    notify_cooldown_sec:parseInt(v("esc-g-cooldown-sec")?.value)||300,
  };
  const r=await fetch("/api/settings/escalation-defaults/apply-all",{method:"POST",headers:authHeaders(),body:JSON.stringify(payload)});
  setStatus("s-esc-status",r.ok?"Applied to all devices ✓":"Failed",r.ok);
}

async function loadEscDeviceTable(){
  try{
    const devR=await fetch("/api/devices",{headers:{"X-Session-Token":getSession()}});
    const devices=await devR.json();
    const tbody=v("esc-device-tbody"); if(!tbody) return;
    const notifMap=await getNotifyMap(devices);
    tbody.innerHTML=devices.map(d=>{
      const n=notifMap[d.id]||{};
      const lv=n.escalation_levels||0;
      return `<tr ${MonFilter.attrs(d)}>
        <td><strong>${esc(d.name)}</strong>${MonFilter.sub(d)}</td>
        <td>${lv>0?`<span style="color:#F2B84B">${lv} level${lv>1?"s":""}</span>`:"<span style='color:var(--text-muted)'>Off</span>"}</td>
        <td style="font-size:12px">${lv>=1?`${n.escalation_after_sec_l1||60}s`:"—"}</td>
        <td style="font-size:12px">${lv>=2?`${n.escalation_after_sec_l2||600}s`:"—"}</td>
        <td><button class="btn secondary small" onclick="openSettNotify('${esc(d.id)}','${esc(d.name)}')">Edit</button></td>
      </tr>`;
    }).join("")||`<tr><td colspan="5" style="color:var(--text-muted);text-align:center;padding:16px">No devices</td></tr>`;
    MonFilter.mount("mf-esc","tab-escalation");
  }catch(e){}
}

/* ═══════════════════════════════════════════════════════════
   NOTIFICATION TEMPLATES
═══════════════════════════════════════════════════════════ */
let _tmplData = {templates:{}, placeholders:[]};
let _tmplEditingState = null;

const TMPL_STATE_LABELS = {warning:"Warning", critical:"Critical", offline:"Offline", recovered:"Recovered"};
const TMPL_STATE_COLORS = {warning:"#F2B84B", critical:"#FF5C5C", offline:"#888888", recovered:"#3DD68C"};

async function loadNotificationTemplatesTab(){
  try{
    const r = await fetch("/api/settings/notification-templates", {headers: authHeaders()});
    if(!r.ok) return;
    _tmplData = await r.json();
    renderPlaceholderRef();
    renderTmplStateCards();
  }catch(e){}
  loadCustomPlaceholders();
}

/* ── Custom placeholders (V8.4): add/edit/remove ──────────────────────── */
let _customPhList = [];
let _customPhEditKey = null;  // null = adding new; set = editing this existing key

async function loadCustomPlaceholders(){
  const c = v("custom-ph-list"); if(!c) return;
  try{
    const r = await fetch("/api/settings/custom-placeholders", {headers: authHeaders()});
    _customPhList = r.ok ? await r.json() : [];
  }catch(e){ _customPhList = []; }

  if(!_customPhList.length){
    c.innerHTML = `<p style="font-size:12.5px;color:var(--text-muted);">None yet — click "Add new" above to create one.</p>`;
    return;
  }
  // V8.4 UX: Remove (−) sits on the LEFT of each row, Add/Edit affordance
  // (clicking the row body) effectively on the right side via the pencil
  // icon -- matches the layout convention requested for this feature.
  c.innerHTML = _customPhList.map(p => `
    <div style="display:flex;align-items:center;gap:10px;padding:7px 10px;border:1px solid var(--border);
                border-radius:var(--radius-sm);background:var(--bg-card,#1a1f2b);">
      <button type="button" onclick="removeCustomPh('${esc(p.key)}')" title="Remove this custom placeholder"
              style="background:var(--status-critical);color:#fff;border:none;border-radius:50%;
                     width:20px;height:20px;min-width:20px;line-height:1;font-size:14px;cursor:pointer;
                     display:flex;align-items:center;justify-content:center;padding:0;">&#8722;</button>
      <div style="flex:1;min-width:0;cursor:pointer;" onclick="openCustomPhModal('${esc(p.key)}')" title="Click to edit">
        <code style="font-family:var(--font-mono);font-size:12px;color:var(--accent);">{{${esc(p.key)}}}</code>
        <span style="font-size:12.5px;color:var(--text-secondary);margin-left:8px;">${esc(p.value)}</span>
        ${p.description ? `<div style="font-size:11px;color:var(--text-muted);">${esc(p.description)}</div>` : ""}
      </div>
      <button type="button" class="btn secondary small" onclick="openCustomPhModal('${esc(p.key)}')"
              style="width:26px;height:26px;padding:0;display:flex;align-items:center;justify-content:center;"
              title="Edit">&#9998;</button>
    </div>`).join("");
}

function openCustomPhModal(editKey){
  _customPhEditKey = editKey || null;
  v("custom-ph-error").textContent = "";
  const keyField = v("custom-ph-key");
  if(_customPhEditKey){
    const p = _customPhList.find(x => x.key === _customPhEditKey) || {};
    v("custom-ph-title").textContent = `Edit {{${_customPhEditKey}}}`;
    keyField.value = _customPhEditKey;
    keyField.disabled = true;  // renaming a key = delete + add new, to avoid ambiguity
    v("custom-ph-value").value = p.value || "";
    v("custom-ph-desc").value  = p.description || "";
  } else {
    v("custom-ph-title").textContent = "Add custom placeholder";
    keyField.disabled = false;
    keyField.value = "";
    v("custom-ph-value").value = "";
    v("custom-ph-desc").value  = "";
  }
  v("custom-ph-modal").classList.remove("hidden");
  if(!_customPhEditKey) setTimeout(() => keyField.focus(), 50);
}
function closeCustomPhModal(){
  v("custom-ph-modal").classList.add("hidden");
  _customPhEditKey = null;
}

// V8.4: live duplicate check as the admin types a NEW key, against both
// built-in placeholders (_tmplData.placeholders, already loaded) and
// existing custom ones -- immediate feedback rather than waiting for
// the save round-trip to find out.
function checkCustomPhKeyLive(){
  if(_customPhEditKey) return;  // editing an existing key -- field is disabled, nothing to check
  const key = (v("custom-ph-key")?.value || "").trim();
  const err = v("custom-ph-error");
  if(!key){ err.textContent = ""; return; }
  const builtIn = (_tmplData.placeholders||[]).some(p => !p.custom && p.key === key);
  const custom  = _customPhList.some(p => p.key === key);
  if(builtIn) err.textContent = `"${key}" is already a built-in placeholder — choose a different name.`;
  else if(custom) err.textContent = `A custom placeholder named "${key}" already exists.`;
  else err.textContent = "";
}

async function saveCustomPh(){
  const key   = (v("custom-ph-key").value || "").trim();
  const value = v("custom-ph-value").value || "";
  const desc  = v("custom-ph-desc").value || "";
  const err   = v("custom-ph-error");
  if(!key){ err.textContent = "Key is required."; return; }
  if(!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(key)){
    err.textContent = "Key must start with a letter and contain only letters, numbers, and underscores.";
    return;
  }
  const url    = _customPhEditKey ? `/api/settings/custom-placeholders/${encodeURIComponent(_customPhEditKey)}` : "/api/settings/custom-placeholders";
  const method = _customPhEditKey ? "PUT" : "POST";
  const r = await fetch(url, {method, headers: authHeaders(), body: JSON.stringify({key, value, description: desc})});
  if(!r.ok){
    const data = await r.json().catch(()=>({}));
    err.textContent = data.error || `Save failed (${r.status})`;
    return;
  }
  closeCustomPhModal();
  await loadNotificationTemplatesTab();  // refreshes both the custom list and the merged chip/reference list
}

async function removeCustomPh(key){
  if(!confirm(`Remove the custom placeholder {{${key}}}? Any template still referencing it will show the literal text instead of a value.`)) return;
  const r = await fetch(`/api/settings/custom-placeholders/${encodeURIComponent(key)}`, {method:"DELETE", headers: authHeaders()});
  if(r.ok) loadNotificationTemplatesTab();
}

function renderPlaceholderRef(){
  const c = v("tmpl-placeholder-ref"); if(!c) return;
  const rows = _tmplData.placeholders.map(p => `
    <tr>
      <td><code style="font-family:var(--font-mono);font-size:12px;color:var(--accent);">{{${esc(p.key)}}}</code>${p.custom ? ' <span style="color:var(--accent);font-size:10px;" title="Custom placeholder">&#9733; custom</span>' : ''}</td>
      <td>${p.required
        ? '<span style="font-size:11px;color:#F2B84B;font-weight:600;">Required</span>'
        : '<span style="font-size:11px;color:var(--text-muted);">Optional</span>'}</td>
      <td style="font-size:12px;color:var(--text-secondary);">${esc(p.description)}${p.key==='portal_url' ? ' <strong>(the dashboard link)</strong>' : ''}</td>
      <td style="font-size:12px;color:var(--text-muted);font-family:var(--font-mono);">${esc(p.example)}</td>
    </tr>`).join("");
  c.innerHTML = `
    <details>
      <summary style="cursor:pointer;font-size:13px;font-weight:600;padding:8px 0;">
        📋 Available placeholders (${_tmplData.placeholders.length}) — click to expand
      </summary>
      <div style="overflow-x:auto;margin-top:8px;">
        <table class="data-table">
          <thead><tr><th>Placeholder</th><th>Required?</th><th>Description</th><th>Example</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </details>`;
}

function renderTmplStateCards(){
  const c = v("tmpl-states-container"); if(!c) return;
  const states = ["warning","critical","offline","recovered"];
  c.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;">
    ${states.map(state => {
      const t = _tmplData.templates[state] || {};
      const col = TMPL_STATE_COLORS[state];
      const badge = t.is_customized
        ? (t.override_disabled
            ? '<span style="font-size:11px;color:var(--text-muted);">Customized (currently off)</span>'
            : '<span style="font-size:11px;color:#3DD68C;font-weight:600;">✓ Customized</span>')
        : '<span style="font-size:11px;color:var(--text-muted);">Using default</span>';
      return `<div style="border:1px solid ${col}44;border-left:3px solid ${col};border-radius:var(--radius-sm);padding:14px;">
        <div style="font-size:14px;font-weight:700;color:${col};margin-bottom:4px;">${TMPL_STATE_LABELS[state]}</div>
        <div style="margin-bottom:12px;">${badge}</div>
        <button class="btn secondary small" onclick="openTmplEditModal('${state}')">Edit template</button>
      </div>`;
    }).join("")}
  </div>`;
}

function openTmplEditModal(state){
  _tmplEditingState = state;
  const t = _tmplData.templates[state] || {};
  v("tmpl-edit-title").textContent = `Edit ${TMPL_STATE_LABELS[state]} template`;
  v("tmpl-enabled").checked = t.is_customized ? !t.override_disabled : false;
  v("tmpl-subject").value = t.subject_template || "";
  v("tmpl-text").value    = t.text_template || "";
  v("tmpl-html").value    = t.html_template || "";
  v("tmpl-validation-hints").innerHTML = "";
  v("tmpl-preview-subject").textContent = "";
  v("tmpl-preview-html").srcdoc = "";
  _tmplLastFocusedField = "tmpl-text";  // sensible default before the admin clicks into a field
  renderTmplChips();
  _wireTmplAutocomplete();
  _wireTmplAutoPreview();
  v("tmpl-edit-modal").classList.remove("hidden");
  previewTmpl();
}

function closeTmplEditModal(){
  v("tmpl-edit-modal").classList.add("hidden");
  _tmplEditingState = null;
}

/* ── placeholder chips: click "+" or drag onto Subject/Text/HTML ──────── */
let _tmplLastFocusedField = "tmpl-text";
const TMPL_FIELD_IDS = ["tmpl-subject", "tmpl-text", "tmpl-html"];

function _insertAtCursor(fieldId, text){
  const el = v(fieldId);
  if(!el) return;
  const start = el.selectionStart ?? el.value.length;
  const end   = el.selectionEnd   ?? el.value.length;
  el.value = el.value.slice(0, start) + text + el.value.slice(end);
  const newPos = start + text.length;
  el.focus();
  el.setSelectionRange(newPos, newPos);
}

/* ── "{{" autocomplete dropdown (V8.4) ────────────────────────────────
   Works for both <input> (subject) and <textarea> (text/html) via a
   hidden "mirror" element styled identically to the real field: we copy
   the text up to the caret into the mirror, measure a marker span's
   position inside it, and use that (plus the real field's own
   getBoundingClientRect()) to place the dropdown right at the caret --
   this is the standard caret-coordinate technique, adapted to need no
   external library since this codebase deliberately has none. */
let _acOpen = false, _acItems = [], _acActiveIdx = -1, _acFieldId = null, _acTriggerStart = -1;

function _getCaretCoords(el){
  const isTextarea = el.tagName === "TEXTAREA";
  const mirror = document.createElement("div");
  const cs = getComputedStyle(el);
  // Copy every style property that affects text layout/wrapping/font
  // metrics -- if the mirror's text doesn't wrap identically to the
  // real field, the measured caret position would be wrong.
  ["boxSizing","width","paddingTop","paddingRight","paddingBottom","paddingLeft",
   "borderTopWidth","borderRightWidth","borderBottomWidth","borderLeftWidth",
   "fontFamily","fontSize","fontWeight","lineHeight","letterSpacing","textTransform"
  ].forEach(p => mirror.style[p] = cs[p]);
  mirror.style.position = "fixed";
  mirror.style.visibility = "hidden";
  mirror.style.top = "0"; mirror.style.left = "-9999px";
  mirror.style.whiteSpace = isTextarea ? "pre-wrap" : "pre";
  mirror.style.wordWrap = "break-word";
  mirror.style.height = "auto";
  if(isTextarea) mirror.style.width = el.clientWidth + "px";

  const caretPos = el.selectionStart ?? el.value.length;
  const before = el.value.substring(0, caretPos);
  const marker = document.createElement("span");
  marker.textContent = "\u200b"; // zero-width, just a measurement anchor
  mirror.textContent = before;
  mirror.appendChild(marker);
  document.body.appendChild(mirror);

  const fieldRect  = el.getBoundingClientRect();
  const markerRect = marker.getBoundingClientRect();
  const mirrorRect = mirror.getBoundingClientRect();
  const top  = fieldRect.top  + (markerRect.top  - mirrorRect.top)  - el.scrollTop  + (markerRect.height || 16);
  const left = fieldRect.left + (markerRect.left - mirrorRect.left) - el.scrollLeft;
  document.body.removeChild(mirror);
  return {top, left};
}

function _acAllPlaceholders(){
  return _tmplData.placeholders || [];
}

function _acCheckTrigger(){
  const el = v(_acFieldId);
  if(!el) return _acClose();
  const caretPos = el.selectionStart ?? el.value.length;
  const before = el.value.substring(0, caretPos);
  // Match a "{{" not yet closed by "}}", optionally followed by partial
  // word characters typed so far (the filter prefix) -- and nothing else
  // in between (a space or another "{" breaks out of trigger mode).
  const m = before.match(/\{\{([a-zA-Z0-9_]*)$/);
  if(!m) return _acClose();

  const prefix = m[1].toLowerCase();
  _acTriggerStart = caretPos - m[0].length;  // index of the opening "{{"
  _acItems = _acAllPlaceholders().filter(p => p.key.toLowerCase().includes(prefix));
  if(!_acItems.length) return _acClose();

  _acOpen = true;
  _acActiveIdx = 0;
  _acRender();
}

function _acRender(){
  const box = v("tmpl-autocomplete");
  const el  = v(_acFieldId);
  if(!box || !el) return;
  box.innerHTML = _acItems.map((p, i) => `
    <div data-idx="${i}" onmousedown="event.preventDefault(); _acSelect(${i})"
         style="padding:6px 10px;font-size:12px;cursor:pointer;display:flex;justify-content:space-between;gap:10px;
                ${i === _acActiveIdx ? "background:var(--accent);color:#fff;" : ""}">
      <code style="font-family:var(--font-mono);">${esc(p.key)}${p.custom ? " \u2605" : ""}</code>
      <span style="opacity:.75;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:140px;">${esc(p.description||"")}</span>
    </div>`).join("");
  const coords = _getCaretCoords(el);
  box.style.top  = coords.top + "px";
  box.style.left = coords.left + "px";
  box.classList.remove("hidden");
}

function _acClose(){
  _acOpen = false; _acItems = []; _acActiveIdx = -1; _acTriggerStart = -1;
  const box = v("tmpl-autocomplete");
  if(box) box.classList.add("hidden");
}

function _acSelect(idx){
  const el = v(_acFieldId);
  const item = _acItems[idx];
  if(!el || !item) return _acClose();
  const caretPos = el.selectionStart ?? el.value.length;
  const token = `{{${item.key}}}`;
  el.value = el.value.slice(0, _acTriggerStart) + token + el.value.slice(caretPos);
  const newPos = _acTriggerStart + token.length;
  el.focus();
  el.setSelectionRange(newPos, newPos);
  _acClose();
}

function _acKeydown(ev){
  if(!_acOpen) return;
  if(ev.key === "ArrowDown"){ ev.preventDefault(); _acActiveIdx = (_acActiveIdx+1) % _acItems.length; _acRender(); }
  else if(ev.key === "ArrowUp"){ ev.preventDefault(); _acActiveIdx = (_acActiveIdx-1+_acItems.length) % _acItems.length; _acRender(); }
  else if(ev.key === "Enter" || ev.key === "Tab"){ ev.preventDefault(); _acSelect(_acActiveIdx); }
  else if(ev.key === "Escape"){ _acClose(); }
}

function _wireTmplAutocomplete(){
  TMPL_FIELD_IDS.forEach(id => {
    const el = v(id);
    if(!el || el.dataset.acWired) return;
    el.dataset.acWired = "1";
    el.addEventListener("input", () => { _acFieldId = id; _acCheckTrigger(); });
    el.addEventListener("keydown", _acKeydown);
    el.addEventListener("blur", () => setTimeout(_acClose, 150));  // delay so a click on the dropdown still registers
  });
  document.addEventListener("click", ev => {
    if(_acOpen && !ev.target.closest("#tmpl-autocomplete") && !TMPL_FIELD_IDS.includes(ev.target.id)) _acClose();
  });
}

function insertPlaceholderChip(key){
  _insertAtCursor(_tmplLastFocusedField, `{{${key}}}`);
}

// V8.4: strips every occurrence of {{key}} from the currently-focused
// field -- the "-" counterpart to insertPlaceholderChip's "+". Removes
// all occurrences rather than just the last-inserted one, since "take
// this placeholder out of my template" is the more predictable reading
// once there may be several already in the text.
function removePlaceholderChip(key){
  const el = v(_tmplLastFocusedField);
  if(!el) return;
  const token = `{{${key}}}`;
  if(!el.value.includes(token)) return;
  el.value = el.value.split(token).join("");
  el.focus();
}

function renderTmplChips(){
  const c = v("tmpl-chip-list"); if(!c) return;
  c.innerHTML = _tmplData.placeholders.map(p => `
    <span class="tmpl-chip" draggable="true" data-key="${esc(p.key)}"
          title="${esc(p.description)}${p.required ? ' (required)' : ' (optional)'}"
          style="display:inline-flex;align-items:center;gap:5px;background:var(--bg-card,#1a1f2b);
                 border:1px solid ${p.custom ? 'var(--accent)' : (p.required ? '#F2B84B66' : 'var(--border)')};
                 border-radius:14px;padding:3px 5px;font-size:11.5px;font-family:var(--font-mono);
                 cursor:grab;user-select:none;">
      <button type="button" onclick="removePlaceholderChip('${esc(p.key)}')"
              title="Remove from ${_tmplLastFocusedField.replace('tmpl-','')}"
              style="background:transparent;color:var(--status-critical);border:1px solid var(--status-critical);
                     border-radius:50%;width:16px;height:16px;min-width:16px;line-height:1;font-size:12px;
                     cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;">&#8722;</button>
      <span style="padding:0 2px;">${esc(p.key)}${p.custom ? ' <span style="color:var(--accent);">&#9733;</span>' : ''}</span>
      <button type="button" onclick="insertPlaceholderChip('${esc(p.key)}')"
              title="Insert into ${_tmplLastFocusedField.replace('tmpl-','')}"
              style="background:var(--accent);color:#fff;border:none;border-radius:50%;
                     width:16px;height:16px;min-width:16px;line-height:1;font-size:12px;cursor:pointer;
                     display:flex;align-items:center;justify-content:center;padding:0;">+</button>
    </span>`).join("");

  // Drag source: each chip carries its own {{token}} as the drag payload
  c.querySelectorAll(".tmpl-chip").forEach(chip => {
    chip.addEventListener("dragstart", ev => {
      ev.dataTransfer.setData("text/plain", `{{${chip.dataset.key}}}`);
      ev.dataTransfer.effectAllowed = "copy";
    });
  });

  // Drop targets + focus tracking, wired once per modal-open (fields are
  // static elements that already exist in the DOM, safe to re-bind).
  TMPL_FIELD_IDS.forEach(id => {
    const el = v(id);
    if(!el || el.dataset.tmplWired) return;
    el.dataset.tmplWired = "1";
    el.addEventListener("focus", () => {
      _tmplLastFocusedField = id;
      c.querySelectorAll(".tmpl-chip button").forEach(btn => {
        const isRemove = btn.textContent.trim() === "\u2212";
        btn.title = `${isRemove ? "Remove from" : "Insert into"} ${id.replace("tmpl-","")}`;
      });
    });
    el.addEventListener("dragover", ev => ev.preventDefault());
    el.addEventListener("drop", ev => {
      ev.preventDefault();
      const text = ev.dataTransfer.getData("text/plain");
      if(text){ _tmplLastFocusedField = id; _insertAtCursor(id, text); }
    });
  });
}

// V8.4: preview now updates live as the admin types (debounced 500ms so
// it doesn't fire a network request on every keystroke), rather than
// requiring a manual "Refresh preview" click.
let _tmplPreviewDebounce = null;
function _wireTmplAutoPreview(){
  TMPL_FIELD_IDS.forEach(id => {
    const el = v(id);
    if(!el || el.dataset.previewWired) return;
    el.dataset.previewWired = "1";
    el.addEventListener("input", () => {
      clearTimeout(_tmplPreviewDebounce);
      _tmplPreviewDebounce = setTimeout(previewTmpl, 500);
    });
  });
}

async function previewTmpl(){
  if(!_tmplEditingState) return;
  const body = {
    subject_template: v("tmpl-subject").value,
    text_template:    v("tmpl-text").value,
    html_template:    v("tmpl-html").value,
  };
  try{
    const r = await fetch(`/api/settings/notification-templates/${_tmplEditingState}/preview`, {
      method:"POST", headers:{...authHeaders(),"Content-Type":"application/json"}, body:JSON.stringify(body)
    });
    const data = await r.json();
    if(!r.ok){ showToast(data.error||"Preview failed","error"); return; }
    v("tmpl-preview-subject").textContent = "Subject: " + data.subject;
    v("tmpl-preview-html").srcdoc = data.html;
  }catch(e){ showToast("Preview failed","error"); }
}

async function saveTmpl(){
  if(!_tmplEditingState) return;
  const body = {
    subject_template: v("tmpl-subject").value,
    text_template:    v("tmpl-text").value,
    html_template:    v("tmpl-html").value,
    enabled:          v("tmpl-enabled").checked,
  };
  try{
    const r = await fetch(`/api/settings/notification-templates/${_tmplEditingState}`, {
      method:"POST", headers:{...authHeaders(),"Content-Type":"application/json"}, body:JSON.stringify(body)
    });
    const data = await r.json();
    if(!r.ok){ showToast(data.error||"Save failed","error"); return; }

    const hints = [];
    for(const field of ["subject","text","html"]){
      (data.unknown_placeholders[field]||[]).forEach(p =>
        hints.push(`<span style="color:#FF8C00;">⚠ Unknown placeholder <code>{{${esc(p)}}}</code> in ${field} — check spelling (see the list above).</span>`));
    }
    if(hints.length){
      v("tmpl-validation-hints").innerHTML = hints.join("<br>");
      showToast("Saved — but check the warnings below before closing","warning");
    } else {
      showToast("Template saved","success");
      closeTmplEditModal();
    }
    await loadNotificationTemplatesTab();
  }catch(e){ showToast("Save failed","error"); }
}

async function resetTmpl(){
  if(!_tmplEditingState) return;
  if(!confirm(`Reset the ${TMPL_STATE_LABELS[_tmplEditingState]} template to Net-monit's built-in default? Your customization will be deleted.`)) return;
  try{
    const r = await fetch(`/api/settings/notification-templates/${_tmplEditingState}/reset`, {
      method:"POST", headers: authHeaders()
    });
    if(!r.ok) throw new Error();
    showToast("Reset to default","success");
    closeTmplEditModal();
    await loadNotificationTemplatesTab();
  }catch(e){ showToast("Reset failed","error"); }
}

/* ═══════════════════════════════════════════════════════════
   THRESHOLDS  (FIXED save)
═══════════════════════════════════════════════════════════ */
let _globalThresh={};
async function loadThreshTab(){
  setThrView(thrView());
  setTimeout(()=>loadScopedThresholds(),0);
  try{
    const r=await fetch("/api/settings/thresholds",{headers:{"X-Session-Token":getSession()}});
    _globalThresh=r.ok?await r.json():{};
  }catch(e){_globalThresh={};}
  await renderGlobalThreshTable();
  loadThreshDeviceTable();
}
const GT_IDS={en:"gt-en-",w:"gt-w-",c:"gt-c-"};
async function renderGlobalThreshTable(){
  const wrap=v("global-thresh-wrap"); if(!wrap) return;
  let meta;
  try{ meta=await ThrUI.load(); }
  catch(e){ wrap.innerHTML='<div style="color:var(--status-critical);padding:12px">Could not load the metric list from the server ('+ThrUI.esc(e.message)+'). Reload the page.</div>'; return; }
  const sect=(title,sub,keys,scope,noun)=>{ const one=noun==="devices"?"device":"site"; return `<div class="thr-sec" data-scope="${scope}">
    <h3 style="font-size:15px;margin:2px 0 2px">${title}</h3>
    <p style="font-size:12px;color:var(--text-muted);margin:0 0 8px">${sub} Hover or click the <span class="thr-i" style="pointer-events:none">!</span> beside a metric for its meaning, allowed range and recommended values.</p>
    <div style="overflow-x:auto">${ThrUI.tableHTML(meta,keys,_globalThresh,GT_IDS,{wait:false})}</div>
    <div class="thr-actions">
      <button type="button" class="btn primary" id="btn-save-thr-${scope}" onclick="saveGlobalThresh('${scope}')">Save ${one} defaults</button>
      <button type="button" class="btn secondary" id="btn-apply-thr-${scope}" onclick="applyThreshToAll('${scope}')">Apply to all ${noun}</button>
      <button type="button" class="btn secondary" id="btn-reset-thr-${scope}" onclick="resetGlobalThresh('${scope}')">Fill recommended values</button>
    </div>
    <p style="font-size:12px;color:var(--text-muted);margin:6px 0 0"><strong>Save</strong> keeps these as the defaults. <strong>Apply to all ${noun}</strong> also removes every per-${one} override of these metrics, so all ${noun} use these values.</p>
  </div>`; };
  wrap.innerHTML=
    sect("Device metrics","Used by monitored devices: ping, SNMP, SSH, PowerShell, disk.",meta.device_metrics,"devices","devices")+
    sect("Website (site) metrics","Used by every site on the Sites page: response time, SSL certificate days left, SSL handshake, DNS lookup and TCP connect.",meta.site_metrics,"sites","sites");
}
async function saveGlobalThresh(scope){
  const meta=ThrUI.get();
  if(!meta){setStatus("s-thresh-status","Metric list not loaded yet",false);return;}
  // scope "devices" / "sites" saves only that category's table and keeps the other category's saved values;
  // no scope (older callers) saves both tables.
  const keys=scope==="sites"?meta.site_metrics:scope==="devices"?meta.device_metrics:[...meta.device_metrics,...meta.site_metrics];
  const {thresholds,errors}=ThrUI.collect(meta,keys,GT_IDS,{wait:false});
  if(errors.length){ setStatus("s-thresh-status",errors[0],false); return; }
  let body=thresholds;
  if(scope){ body={}; for(const k in _globalThresh){ if(!keys.includes(k)) body[k]=_globalThresh[k]; } Object.assign(body,thresholds); }
  const r=await fetch("/api/settings/thresholds",{method:"POST",headers:authHeaders(),body:JSON.stringify(body)});
  if(!r.ok){
    let msg=`Save failed (${r.status})`;
    try{ const j=await r.json(); if(j&&j.error) msg=j.error; }catch(_){}
    setStatus("s-thresh-status",msg,false);
    return;
  }
  _globalThresh=body;
  setStatus("s-thresh-status","Saved \u2713"+(scope?" ("+scope+")":""),true);
  loadThreshDeviceTable();
}
async function applyThreshToAll(scope){
  const meta=ThrUI.get();
  if(!meta){setStatus("s-thresh-status","Metric list not loaded yet",false);return;}
  const keys=scope==="sites"?meta.site_metrics:meta.device_metrics;
  const noun=scope==="sites"?"sites":"devices";
  const {thresholds,errors}=ThrUI.collect(meta,keys,GT_IDS,{wait:false});
  if(errors.length){ setStatus("s-thresh-status",errors[0],false); return; }
  if(!confirm("Apply these "+(scope==="sites"?"website":"device")+" threshold values to ALL "+noun+"?\n\nThey become the default, and any per-"+(scope==="sites"?"site":"device")+" override of these metrics is removed. Wait times are kept."))
    return;
  const r=await fetch("/api/settings/thresholds/apply",{method:"POST",headers:authHeaders(),body:JSON.stringify({scope,thresholds})});
  let j={}; try{ j=await r.json(); }catch(_){}
  if(!r.ok||!j.ok){ setStatus("s-thresh-status",(j&&j.error)||("Apply failed ("+r.status+")"),false); return; }
  setStatus("s-thresh-status","Applied to "+j.count+" "+noun+" \u2713 ("+j.overrides_removed+" override"+(j.overrides_removed===1?"":"s")+" removed)",true);
  await loadThreshTab();
}
function resetGlobalThresh(scope){
  const meta=ThrUI.get(); if(!meta) return;
  const keys=scope==="sites"?meta.site_metrics:scope==="devices"?meta.device_metrics:[...meta.device_metrics,...meta.site_metrics];
  ThrUI.fillRecommended(meta,keys,GT_IDS);
  setStatus("s-thresh-status","Filled with the recommended values \u2014 click Save (or Apply to all) to keep them",true);
}
// V11.3 patch 03: Devices | Sites switch. Only the chosen category's defaults and monitors are shown (CSS keys off data-view).
function thrView(){ try{ return sessionStorage.getItem("thr-view")==="sites"?"sites":"devices"; }catch(_){ return "devices"; } }
function setThrView(view){
  view=view==="sites"?"sites":"devices";
  const root=v("thr-root"); if(root) root.setAttribute("data-view",view);
  ["devices","sites"].forEach(k=>{ const b=v("thr-tab-"+k); if(b){ b.setAttribute("aria-selected",k===view?"true":"false"); b.classList.toggle("active",k===view); } });
  try{ sessionStorage.setItem("thr-view",view); }catch(_){}
}
async function loadThreshDeviceTable(){
  try{
    const meta=await ThrUI.load();
    const devR=await fetch("/api/devices",{headers:{"X-Session-Token":getSession()}});
    const devices=await devR.json();
    const host=v("thresh-device-groups"); if(!host) return;
    const notifMap=await getNotifyMap(devices);
    const TYPE={url:"Website",ping:"Ping",snmp:"SNMP",ssh:"SSH",powershell:"PowerShell",disk_usage:"Disk"};
    const row=d=>{
      const t=(notifMap[d.id]||{}).thresholds||{};
      return `<tr ${MonFilter.attrs(d)}>
        <td style="min-width:150px"><strong>${esc(d.name)}</strong>${MonFilter.sub(d)}</td>
        <td><span class="thr-method">${esc(TYPE[d.method||"ping"]||d.method||"")}</span></td>
        <td>${ThrUI.summaryHTML(meta,d.method||"ping",t,_globalThresh)}</td>
        <td><button class="btn secondary small" onclick="openSettNotify('${esc(d.id)}','${esc(d.name)}')">Edit</button></td>
      </tr>`;
    };
    const cat=(title,list,open,scope)=>`<details class="thr-cat" data-scope="${scope}"${open?" open":""}>
      <summary>${title}<span class="thr-cat-count">${list.length} monitor${list.length===1?"":"s"}</span></summary>
      <div style="overflow-x:auto"><table class="data-table" style="margin:0">
        <thead><tr><th>Name</th><th>Type</th><th>Active thresholds \u2014 warning/critical (bold = overridden)</th><th>Edit</th></tr></thead>
        <tbody>${list.map(row).join("")||`<tr><td colspan="4" style="color:var(--text-muted);text-align:center;padding:16px">None yet</td></tr>`}</tbody>
      </table></div></details>`;
    const byType=(a,b)=>String(a.method||"").localeCompare(String(b.method||""))||String(a.name||"").localeCompare(String(b.name||""));
    const devs=devices.filter(d=>(d.method||"")!=="url").sort(byType);
    const sites=devices.filter(d=>(d.method||"")==="url").sort(byType);
    const nd=v("thr-n-devices"), ns=v("thr-n-sites"); if(nd) nd.textContent="("+devs.length+")"; if(ns) ns.textContent="("+sites.length+")";
    host.innerHTML=devices.length?(cat("\uD83D\uDDA5 Devices",devs,true,"devices")+cat("\uD83C\uDF10 Sites",sites,true,"sites")):
      `<div style="color:var(--text-muted);text-align:center;padding:16px">No devices or sites yet</div>`;
    await MonFilter.mount("mf-thr","thresh-device-groups");
    syncThrFilter();
  }catch(e){}
}

/* ═══════════════════════════════════════════════════════════
   DEVICES TAB  (FIXED: credential fields per method)
═══════════════════════════════════════════════════════════ */
const QD_METHOD_FIELDS={
  ping:[],
  snmp:[
    {id:"qd-snmp-community",label:"Community string",placeholder:"public"},
    {id:"qd-snmp-version",label:"SNMP version",placeholder:"2",type:"number"},
  ],
  powershell:[
    {id:"qd-ps-remote",label:"Remote monitoring",type:"select",opts:["false:Local (run PS on this machine)","true:Remote (WinRM)"]},
    {id:"qd-ps-user",label:"Username (DOMAIN\\\\user)",placeholder:"DOMAIN\\\\user"},
    {id:"qd-ps-pass",label:"Password",type:"password",placeholder:""},
  ],
  ssh:[
    {id:"qd-ssh-port",label:"Port",placeholder:"22",type:"number"},
    {id:"qd-ssh-user",label:"Username",placeholder:"monitor"},
    {id:"qd-ssh-pass",label:"Password",type:"password",placeholder:""},
    {id:"qd-ssh-key",label:"Key path (optional)",placeholder:"/home/user/.ssh/id_rsa"},
  ],
  disk_usage:[
    {id:"qd-disk-os",label:"OS (windows/linux)",placeholder:"windows"},
    {id:"qd-disk-path",label:"Path (UNC or mount)",placeholder:"\\\\\\\\server\\\\share",wide:true},
    {id:"qd-disk-user",label:"Username",placeholder:""},
    {id:"qd-disk-pass",label:"Password",type:"password",placeholder:""},
  ],
};

// Metrics available per method — for the "what to monitor" checkboxes
const QD_METHOD_METRICS={
  ping:       [{id:"latency_ms",label:"Latency (ms)",chk:true},{id:"packet_loss_pct",label:"Packet Loss (%)",chk:true}],
  snmp:       [{id:"latency_ms",label:"Latency",chk:true},{id:"packet_loss_pct",label:"Packet Loss",chk:true},{id:"cpu_pct",label:"CPU %",chk:true},{id:"bandwidth_pct",label:"Bandwidth %",chk:true}],
  powershell: [{id:"latency_ms",label:"Latency",chk:true},{id:"packet_loss_pct",label:"Packet Loss",chk:true},{id:"cpu_pct",label:"CPU %",chk:true},{id:"memory_pct",label:"Memory %",chk:true},{id:"disk_pct",label:"Disk %",chk:true},{id:"bandwidth_pct",label:"Bandwidth %",chk:false}],
  ssh:        [{id:"latency_ms",label:"Latency",chk:true},{id:"packet_loss_pct",label:"Packet Loss",chk:true},{id:"cpu_pct",label:"CPU %",chk:true},{id:"memory_pct",label:"Memory %",chk:true},{id:"disk_pct",label:"Disk %",chk:true}],
  disk_usage: [{id:"disk_pct",label:"Disk %",chk:true},{id:"latency_ms",label:"Latency",chk:true}],
};

function renderQdMethodFields(){
  const m=v("qd-method")?.value||"ping";
  const fields=QD_METHOD_FIELDS[m]||[];
  const c=v("qd-cred-fields");
  if(c){
    c.innerHTML=fields.length?`
      <div style="margin-top:10px;padding:10px;border:1px solid var(--border);border-radius:var(--radius-sm);background:rgba(255,255,255,.02);">
        <p style="font-size:11.5px;color:var(--text-muted);margin-bottom:8px;">🔒 Credentials for ${m}</p>
        <div class="form-grid">
          ${fields.map(f=>{
            if(f.type==="select"){
              return `<div class="field" style="${f.wide?"grid-column:1/-1":""}"><label>${f.label}</label>
                <select id="${f.id}">${f.opts.map(o=>{const[val,lbl]=o.split(":");return`<option value="${val}">${lbl}</option>`}).join("")}</select></div>`;
            }
            return `<div class="field" style="${f.wide?"grid-column:1/-1":""}"><label>${f.label}</label>
              <input id="${f.id}" type="${f.type||"text"}" placeholder="${f.placeholder||""}"></div>`;
          }).join("")}
        </div>
      </div>`:""
  }
  // Render what-to-monitor checkboxes
  const metrics=QD_METHOD_METRICS[m]||[];
  const mc=v("qd-monitor-metrics");
  if(mc){
    mc.innerHTML=metrics.length?`
      <div style="margin-top:10px;padding:10px;border:1px solid var(--border);border-radius:var(--radius-sm);background:rgba(255,255,255,.02);">
        <p style="font-size:11.5px;color:var(--text-muted);margin-bottom:8px;">📊 Select metrics to monitor:</p>
        <div style="display:flex;flex-wrap:wrap;gap:8px;">
          ${metrics.map(mt=>`
            <label style="display:flex;align-items:center;gap:5px;font-size:12.5px;cursor:pointer;
              padding:4px 10px;border-radius:4px;border:1px solid var(--border);background:var(--bg-hover);">
              <input type="checkbox" id="qd-m-${mt.id}" ${mt.chk?"checked":""}> ${mt.label}</label>`).join("")}
        </div>
      </div>`:"";
  }
}

function _qdVal(id){const e=v(id);return e?e.value.trim():"";}

async function settingsAddDevice(){
  const m=v("qd-method")?.value||"ping";
  const device={
    id:_qdVal("qd-id"),name:_qdVal("qd-name"),host:_qdVal("qd-host"),
    type:v("qd-type")?.value||"network",method:m,
  };
  const iv=_qdVal("qd-interval"); if(iv) device.poll_interval_seconds=parseInt(iv);
  if(!device.id||!device.name||!device.host){setStatus("qd-status","ID, name and host required",false);return;}

  // Collect credentials
  if(m==="powershell"){
    device.powershell={remote:_qdVal("qd-ps-remote")==="true",use_winrm:true,username:_qdVal("qd-ps-user")||null,password:_qdVal("qd-ps-pass")||null};
    if(!device.powershell.username) delete device.powershell.username;
    if(!device.powershell.password) delete device.powershell.password;
  } else if(m==="snmp"){
    device.snmp={community:_qdVal("qd-snmp-community")||"public",version:parseInt(_qdVal("qd-snmp-version")||"2")};
  } else if(m==="ssh"){
    device.ssh={port:parseInt(_qdVal("qd-ssh-port")||"22"),username:_qdVal("qd-ssh-user")||"monitor",password:_qdVal("qd-ssh-pass")||null,key_path:_qdVal("qd-ssh-key")||null};
    if(!device.ssh.password) delete device.ssh.password;
    if(!device.ssh.key_path) delete device.ssh.key_path;
  } else if(m==="disk_usage"){
    const path=_qdVal("qd-disk-path");
    if(!path){setStatus("qd-status","Path required for disk method",false);return;}
    device.disk={os:_qdVal("qd-disk-os")||"windows",path,remote:true,username:_qdVal("qd-disk-user")||null,password:_qdVal("qd-disk-pass")||null};
    if(!device.disk.username) delete device.disk.username;
    if(!device.disk.password) delete device.disk.password;
  }

  // Collect monitored metrics
  const metricsEnabled={};
  (QD_METHOD_METRICS[m]||[]).forEach(mt=>{
    const cb=v(`qd-m-${mt.id}`);
    metricsEnabled[mt.id]={enabled:cb?cb.checked:true};
  });
  // Save as initial thresholds config
  device._initial_thresholds=metricsEnabled;

  const r=await fetch("/api/devices",{method:"POST",headers:authHeaders(),body:JSON.stringify(device)});
  if(r.ok){
    // Save initial threshold selection as device notify config
    const thresholds={};
    Object.entries(metricsEnabled).forEach(([k,v2])=>{
      thresholds[k]={enabled:v2.enabled};   // V11.1: was {enabled,w,c} -- keys nothing reads; defaults apply
    });
    await fetch(`/api/devices/${encodeURIComponent(device.id)}/notify`,{
      method:"POST",headers:authHeaders(),
      body:JSON.stringify({notifications_enabled:1,notify_emails:[],escalation_levels:0,
        escalation_emails_l1:[],escalation_emails_l2:[],escalation_emails_l3:[],
        escalation_after_sec_l1:60,escalation_after_sec_l2:600,escalation_after_sec_l3:1200,thresholds})
    });
    setStatus("qd-status",`${device.name} added ✓`,true);
    ["qd-id","qd-name","qd-host","qd-interval"].forEach(id=>{if(v(id))v(id).value="";});
    loadDevicesTab();
  } else {
    const d=await r.json();
    setStatus("qd-status",d.error||"Failed",false);
  }
}

async function loadDevicesTab(){
  try{
    const[devR,statR]=await Promise.all([
      fetch("/api/devices",{headers:{"X-Session-Token":getSession()}}),
      fetch("/api/status",{headers:{"X-Session-Token":getSession()}})
    ]);
    const devices=await devR.json();
    const stat=statR.ok?(await statR.json()).devices:[];
    const statMap=Object.fromEntries(stat.map(d=>[d.device_id,d]));
    const tbodyNet   = v("sett-devices-tbody");
    const tbodySites = v("sett-sites-tbody");
    if(!tbodyNet && !tbodySites) return;

    const STATUS_TEXT={ok:"Healthy",warning:"Warning",critical:"Critical",offline:"Offline",unknown:"Unknown"};   // V11.2: was the raw word "ok"
    const rowHtml = (d) => {
      const s=statMap[d.id]||{};const sc=s.status||"unknown";
      const cols={ok:"var(--status-ok)",warning:"var(--status-warning)",critical:"var(--status-critical)",offline:"var(--text-muted)",unknown:"var(--text-muted)"};
      return `<tr ${MonFilter.attrs(d)}>
        <td><strong>${esc(d.name)}</strong><br><span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">${esc(d.id)}</span></td>
        <td style="font-size:12px">${esc(MonFilter.TYPE_LABELS[d.type]||d.type||"")}</td>
        <td style="font-size:12px">${esc(MonFilter.METHOD_LABELS[d.method]||d.method||"")}</td>
        <td><span style="color:${cols[sc]};font-weight:600">● ${STATUS_TEXT[sc]||sc}</span></td>
        <td>
          <button class="btn secondary small" onclick="settTestDevice('${esc(d.id)}','${esc(d.name)}')">▶ Test</button>
          <span id="st-res-${esc(d.id)}" style="font-size:11px;margin-left:4px;"></span>
        </td>
        <td><button class="btn secondary small" onclick="openSettNotify('${esc(d.id)}','${esc(d.name)}')">⚙ Notify</button></td>
        <td><button class="btn danger small" onclick="settRemoveDevice('${esc(d.id)}','${esc(d.name)}')">Remove</button></td>
      </tr>`;
    };

    const netDevices   = devices.filter(d => (d.method||"") !== "url");
    const siteDevices  = devices.filter(d => (d.method||"") === "url");

    if (tbodyNet) {
      tbodyNet.innerHTML = netDevices.map(rowHtml).join("") ||
        `<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:16px">No network devices yet</td></tr>`;
    }
    if (tbodySites) {
      tbodySites.innerHTML = siteDevices.map(rowHtml).join("") ||
        `<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:16px">No sites yet — add one from the Sites Monitor page</td></tr>`;
    }
    MonFilter.mount("mf-mon","tab-devices");
  }catch(e){console.error("loadDevicesTab",e);}
}
async function settTestDevice(id,name){
  const el=v(`st-res-${id}`);if(el){el.textContent="Testing…";el.style.color="var(--text-muted)";}
  const r=await fetch(`/api/devices/${encodeURIComponent(id)}/test`,{method:"POST",headers:authHeaders()});
  const d=await r.json();
  if(el){el.textContent=d.ok?"✔ PASS":"✖ FAIL";el.style.color=d.ok?"var(--status-ok)":"var(--status-critical)";el.title=d.detail||"";}
  showToast(d.ok?`${name}: PASS — ${d.detail}`:`${name}: FAIL — ${d.detail}`,d.ok?"success":"error");
}
async function settRemoveDevice(id,name){
  if(!confirm(`Remove "${name}"?`)) return;
  const r=await fetch(`/api/devices/${encodeURIComponent(id)}`,{method:"DELETE",headers:authHeaders()});
  if(r.ok){showToast(`${name} removed`,"success");loadDevicesTab();}
  else showToast("Failed","error");
}

/* ═══════════════════════════════════════════════════════════
   USERS
═══════════════════════════════════════════════════════════ */
const SU_ROLE_META = {
  admin:      { label: "⚙ admin",      bg: "rgba(59,139,235,.15)",  fg: "var(--accent)",         bd: "rgba(59,139,235,.3)"  },
  supervisor: { label: "🛡 supervisor", bg: "rgba(158,119,237,.15)", fg: "#9E77ED",               bd: "rgba(158,119,237,.3)" },
  user:       { label: "👁 view",       bg: "rgba(242,184,75,.12)",  fg: "var(--status-warning)", bd: "rgba(242,184,75,.25)" },
};
async function loadUsersTab(){
  try{
    const r=await fetch("/api/admin/users",{headers:{"X-Session-Token":getSession()}});
    if(!r.ok) return;
    const users=await r.json();
    const tbody=v("su-users-tbody"); if(!tbody) return;
    tbody.innerHTML=users.length?users.map(u=>{
      const meta = SU_ROLE_META[u.role] || SU_ROLE_META.user;
      return `<tr>
      <td style="font-weight:600">
        <div style="display:flex;align-items:center;gap:6px;">
          <span>${esc(u.email)}</span>
          <button class="btn secondary small" title="Edit email" onclick="suEditEmail(${u.id},'${esc(u.email)}')" style="padding:1px 7px;">✎</button>
        </div>
      </td>
      <td>
        <select onchange="suChangeRole('${esc(u.email)}', this.value)"
          style="background:${meta.bg};color:${meta.fg};border:1px solid ${meta.bd};border-radius:4px;font-size:11.5px;font-weight:700;padding:3px 6px;">
          <option value="admin"      ${u.role==='admin'?'selected':''}>⚙ admin</option>
          <option value="supervisor" ${u.role==='supervisor'?'selected':''}>🛡 supervisor</option>
          <option value="user"       ${u.role==='user'?'selected':''}>👁 view</option>
        </select>
      </td>
      <td>${u.active?"● Active":"○ Inactive"}</td>
      <td style="display:flex;gap:6px;flex-wrap:wrap;">
        <button class="btn secondary small" onclick="suResetToken('${esc(u.email)}')">🔑 Token</button>
        <button class="btn danger small" onclick="suDeleteUser('${esc(u.email)}')">Remove</button>
      </td>
    </tr>`;
    }).join(""):`<tr><td colspan="4" style="color:var(--text-muted);text-align:center;padding:16px">No users</td></tr>`;
  }catch(e){}
}
async function suEditEmail(userId, currentEmail){
  const newEmail = prompt("Fix the email for this account:", currentEmail);
  if(newEmail===null || newEmail.trim().toLowerCase()===currentEmail.toLowerCase()) return;
  const r = await fetch(`/api/admin/users/${userId}/email`,{method:"PUT",headers:authHeaders(),body:JSON.stringify({email:newEmail.trim()})});
  const d = await r.json();
  if(r.ok){ showToast(`Email updated to ${d.email}`,"success"); loadUsersTab(); }
  else showToast(d.error||"Failed","error");
}
async function suChangeRole(email, newRole){
  if(!confirm(`Change "${email}" to role: ${newRole}?`)) return;
  let token = "";
  try{ const r=await fetch("/api/admin/generate-token",{headers:{"X-Session-Token":getSession()}}); const d=await r.json(); token=d.token||""; }catch(_){}
  const r=await fetch("/api/admin/users",{method:"POST",headers:authHeaders(),body:JSON.stringify({email,role:newRole,token})});
  if(r.ok){ showToast(`${email} \u2192 ${newRole}`,"success"); loadUsersTab(); }
  else { showToast("Failed","error"); loadUsersTab(); }
}
async function suGenToken(){
  try{const r=await fetch("/api/admin/generate-token",{headers:{"X-Session-Token":getSession()}});const d=await r.json();if(d.token){v("su-token").value=d.token;suCheckToken();}}catch(e){}
}
function suCheckToken(){
  const t=v("su-token")?.value||"";const bar=v("su-token-bar");const hint=v("su-token-hint");if(!bar||!hint)return;
  const ok={len:t.length>=8,up:/[A-Z]/.test(t),lo:/[a-z]/.test(t),di:/[0-9]/.test(t)};
  const score=Object.values(ok).filter(Boolean).length;
  bar.style.width=score<=2?"33%":score===3?"66%":"100%";
  bar.style.background=score<=2?"#FF5C5C":score===3?"#F2B84B":"#3DD68C";
  hint.innerHTML=`<span style="color:${ok.len?"#3DD68C":"#FF5C5C"}">8+ chars</span> <span style="color:${ok.up?"#3DD68C":"#FF5C5C"}">A-Z</span> <span style="color:${ok.lo?"#3DD68C":"#FF5C5C"}">a-z</span> <span style="color:${ok.di?"#3DD68C":"#FF5C5C"}">0-9</span>`;
}
async function suAddUser(){
  const email=v("su-email")?.value.trim().toLowerCase()||"";
  const role=v("su-role")?.value||"user";
  const token=v("su-token")?.value.trim()||"";
  if(!email||!token){setStatus("su-status","Email and token required",false);return;}
  if(token.length<8||!/[A-Z]/.test(token)||!/[a-z]/.test(token)||!/[0-9]/.test(token)){setStatus("su-status","Token: 8+ chars, upper+lower+number",false);return;}
  const r=await fetch("/api/admin/users",{method:"POST",headers:authHeaders(),body:JSON.stringify({email,role,token})});
  const d=await r.json();
  if(r.ok){setStatus("su-status",`${email} added${d.welcome_email_sent?" · welcome email sent ✓":""}`,true);if(v("su-email"))v("su-email").value="";if(v("su-token"))v("su-token").value="";loadUsersTab();}
  else setStatus("su-status",d.error||"Failed",false);
}
async function suResetToken(email){
  const t=prompt(`New token for "${email}" (8+ chars, upper+lower+number):`);
  if(t===null)return;
  if(t.length<8||!/[A-Z]/.test(t)||!/[a-z]/.test(t)||!/[0-9]/.test(t)){showToast("Token too weak","error");return;}
  const r=await fetch(`/api/admin/users/${encodeURIComponent(email)}/token`,{method:"PUT",headers:authHeaders(),body:JSON.stringify({token:t})});
  showToast(r.ok?"Token reset ✓":"Failed",r.ok?"success":"error");
}
async function suDeleteUser(email){
  if(!confirm(`Remove "${email}"?`)) return;
  const r=await fetch(`/api/admin/users/${encodeURIComponent(email)}`,{method:"DELETE",headers:authHeaders()});
  if(r.ok){showToast(`${email} removed`,"success");loadUsersTab();}else showToast("Failed","error");
}

/* ═══════════════════════════════════════════════════════════
   AUDIT TAB (split: user/device audit + alert log)
═══════════════════════════════════════════════════════════ */
async function loadAuditTab(){
  loadAuditLog();
}
async function loadAuditLog(){
  try{
    const r=await fetch("/api/audit?limit=300",{headers:{"X-Session-Token":getSession()}});
    const logs=r.ok?await r.json():[];
    // Split into user/device actions vs system events
    const userDevActions=["add_user","delete_user","edit_user_email","reset_token","add_device","edit_device","delete_device","test_device","apply_esc_defaults_all"];
    const userDevLogs=logs.filter(l=>userDevActions.some(a=>l.action===a || l.action?.startsWith(a+"_")));
    const systemLogs=logs.filter(l=>!userDevLogs.includes(l));
    renderAuditTable("audit-user-tbody",userDevLogs,"User and device actions will appear here as they happen — user accounts added or removed, tokens reset, devices added, edited, or deleted.");
    renderAuditTable("audit-device-tbody",systemLogs,"System events will appear here as they happen — config saves, escalation changes, threshold updates.");
  }catch(e){console.error("loadAuditLog",e);}
}
function renderAuditTable(tbodyId,logs,emptyMessage){
  const tbody=v(tbodyId);if(!tbody)return;
  tbody.innerHTML=logs.length?logs.map(l=>`<tr>
    <td style="font-size:11.5px;white-space:nowrap;color:var(--text-muted)">${new Date(l.ts*1000).toLocaleString()}</td>
    <td style="font-family:var(--font-mono);font-size:12px;color:var(--accent)">${esc(l.actor||"system")}</td>
    <td><span class="audit-badge">${esc(l.action||"")}</span></td>
    <td style="font-size:12px">${esc(l.target||"")}</td>
    <td style="font-size:11.5px;color:var(--text-muted)">${esc(l.detail||"")}</td>
  </tr>`).join(""):`<tr><td colspan="5" style="color:var(--text-muted);text-align:center;padding:28px 16px">${esc(emptyMessage||"Events will appear here.")}</td></tr>`;
}

/* ═══════════════════════════════════════════════════════════
   ALERT LOG
═══════════════════════════════════════════════════════════ */
let _allAlerts=[],_alertFilter="all";
async function loadAlerts(){
  try{
    const r=await fetch("/api/alerts?limit=200",{headers:{"X-Session-Token":getSession()}});
    _allAlerts=r.ok?await r.json():[];
    renderAlerts();renderAlertSummary();
  }catch(e){}
}
function filterAlerts(f){
  _alertFilter=f;
  document.querySelectorAll("[id^='af-']").forEach(b=>b.classList.remove("active"));
  const m={all:"all",critical:"crit",warning:"warn",recovered:"rec",offline:"off"};
  v(`af-${m[f]||f}`)?.classList.add("active");
  renderAlerts();
}
function renderAlerts(){
  let rows=_alertFilter==="all"?_allAlerts:_allAlerts.filter(a=>a.state===_alertFilter);
  const q=(v("al-search-box")?.value||"").trim().toLowerCase();
  if(q) rows=rows.filter(a=>(a.device_name||"").toLowerCase().includes(q)||(a.message||"").toLowerCase().includes(q)||(a.metric||"").toLowerCase().includes(q));
  const tbody=v("alerts-tbody");if(!tbody)return;
  const COL={warning:"var(--status-warning)",critical:"var(--status-critical)",recovered:"var(--status-ok)",offline:"var(--text-muted)"};
  tbody.innerHTML=rows.length?rows.map(a=>`<tr>
    <td style="font-size:12px;white-space:nowrap">${new Date(a.ts*1000).toLocaleString()}</td>
    <td>${esc(a.device_name)}</td>
    <td style="font-family:var(--font-mono);font-size:12px">${esc((a.metric||"").replace(/_/g," "))}</td>
    <td><span style="color:${COL[a.state]||"var(--text-secondary)"};font-weight:700">${esc(a.state?.toUpperCase())}</span></td>
    <td style="font-family:var(--font-mono);font-size:12px">${typeof a.value==="number"?a.value.toFixed(1):a.value}</td>
    <td style="color:${a.emailed?"var(--status-ok)":"var(--text-muted)"}">${a.emailed?"✓ sent":"—"}</td>
    <td style="font-size:12px;color:var(--text-muted)">${esc(a.message||"")}</td>
  </tr>`).join(""):`<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:20px">${q||_alertFilter!=="all"?"No alerts match your search/filter.":"No alerts yet."}</td></tr>`;
}
function renderAlertSummary(){
  const now=Date.now()/1000;const day=_allAlerts.filter(a=>a.ts>now-86400);
  v("asum-crit")  && (v("asum-crit").textContent  = day.filter(a=>a.state==="critical").length);
  v("asum-warn")  && (v("asum-warn").textContent  = day.filter(a=>a.state==="warning").length);
  v("asum-rec")   && (v("asum-rec").textContent   = day.filter(a=>a.state==="recovered").length);
  v("asum-email") && (v("asum-email").textContent = day.filter(a=>a.emailed).length);
}

/* ═══════════════════════════════════════════════════════════
   PER-DEVICE NOTIFY MODAL (escalation toggle per device)
═══════════════════════════════════════════════════════════ */
let _snmDeviceId="";
const SNM_ESC={l1:false,l2:false,l3:false};

async function openSettNotify(deviceId,deviceName){
  _snmDeviceId=deviceId;
  if(v("snm-name")) v("snm-name").textContent=deviceName;
  v("sett-notify-modal")?.classList.remove("hidden");
  try{const gr=await fetch("/api/admin/email-groups",{headers:{"X-Session-Token":getSession()}});if(gr.ok){const g=await gr.json();_allKnownEmails=g.all_emails||[];}}catch(_){}
  const r=await fetch(`/api/devices/${encodeURIComponent(deviceId)}/notify`,{headers:{"X-Session-Token":getSession()}});
  const cfg=r.ok?await r.json():{};
  if(v("snm-enabled")) v("snm-enabled").checked=cfg.notifications_enabled!==0;
  if(v("snm-notify-emails")) v("snm-notify-emails").value=fmtEmails(cfg.notify_emails||[]);
  SNM_ESC.l1=(cfg.escalation_levels||0)>=1;
  SNM_ESC.l2=(cfg.escalation_levels||0)>=2;
  SNM_ESC.l3=(cfg.escalation_levels||0)>=3;
  window._snmCfg=cfg;
  const tmSel=v("snm-trigger-mode"); if(tmSel) tmSel.value=cfg.alert_trigger_mode||"sustained";
  const nmSel=v("snm-notify-mode");  if(nmSel) nmSel.value=cfg.alert_notify_mode||"immediate";
  const cdSec=v("snm-cooldown-sec"); if(cdSec) cdSec.value=cfg.notify_cooldown_sec||300;
  renderSnmNotifyEmailPicker(cfg.notify_emails||[]);
  renderSnmEscLevels(cfg);
  renderSnmThresholds(cfg.thresholds||{},deviceId,cfg.escalation_after_sec_l1||60);
  // V8.2: initialize the inline "wait ___ seconds" field next to the
  // trigger-mode dropdown, same pattern as the global Escalation tab.
  const waitField = v("snm-wait-sec");
  if (waitField) waitField.value = cfg.escalation_after_sec_l1 || 60;
  toggleSnmWaitField();
  toggleSnmCooldownField();
}
function toggleSnmWaitField(){
  const mode  = v("snm-trigger-mode")?.value;
  const field = v("snm-wait-field");
  if (field) field.style.display = mode === "sustained" ? "flex" : "none";
}
// V8.4: mirrors toggleSnmWaitField's show/hide pattern for the new
// per-device cooldown seconds input.
function toggleSnmCooldownField(){
  const mode  = v("snm-notify-mode")?.value;
  const field = v("snm-cooldown-field");
  if (field) field.style.display = mode === "cooldown" ? "flex" : "none";
}
function syncSnmWaitToL1(){
  const waitVal = v("snm-wait-sec")?.value;
  const l1 = v("snm-sec-l1");
  if (l1 && waitVal) l1.value = waitVal;
}
function syncL1ToSnmWait(){
  const l1 = v("snm-sec-l1")?.value;
  const waitField = v("snm-wait-sec");
  if (waitField && l1) waitField.value = l1;
}
function renderSnmNotifyEmailPicker(current){
  const c=v("snm-notify-email-picker");if(!c)return;
  if(!_allKnownEmails.length){c.innerHTML="";return;}
  c.innerHTML=`<p style="font-size:11.5px;color:var(--text-muted);margin-bottom:4px;">Quick-select:</p>
    <div style="display:flex;flex-wrap:wrap;gap:4px;">
      ${_allKnownEmails.map(e=>`
        <label style="display:flex;align-items:center;gap:3px;font-size:12px;cursor:pointer;
          padding:2px 8px;border-radius:4px;border:1px solid var(--border);background:var(--bg-hover);
          ${(current||[]).includes(e)?"border-color:var(--accent)":""}">
          <input type="checkbox" data-email="${esc(e)}" data-target="snm-notify-emails"
            ${(current||[]).includes(e)?"checked":""} onchange="_syncEmailCb(this)"> ${esc(e)}</label>`).join("")}
    </div>`;
}
function renderSnmEscLevels(cfg){
  cfg=cfg||{};
  const c=v("snm-esc-container");if(!c)return;
  const defs=[
    {n:1,key:"l1",col:"#F2B84B",sec:cfg.escalation_after_sec_l1||60,emails:cfg.escalation_emails_l1||[],
     sms:cfg.sms_numbers_l1||[],call:cfg.call_numbers_l1||[]},
    {n:2,key:"l2",col:"#FF8C00",sec:cfg.escalation_after_sec_l2||600,emails:cfg.escalation_emails_l2||[],
     sms:cfg.sms_numbers_l2||[],call:cfg.call_numbers_l2||[]},
    {n:3,key:"l3",col:"#FF5C5C",sec:cfg.escalation_after_sec_l3||1200,emails:cfg.escalation_emails_l3||[],
     sms:cfg.sms_numbers_l3||[],call:cfg.call_numbers_l3||[]},
  ];
  c.innerHTML=defs.map(lv=>{
    const on=SNM_ESC[lv.key];
    return `<div style="border:1px solid ${on?lv.col+"44":"var(--border)"};border-radius:var(--radius-sm);
      padding:10px 12px;margin-bottom:8px;border-left:3px solid ${on?lv.col:"var(--border)"};opacity:${on?1:.6}">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
        <label style="cursor:pointer;display:flex;align-items:center;gap:7px;">
          <span class="toggle-sw ${on?"on":""}" id="snm-tog-l${lv.n}" onclick="toggleSnmEsc(${lv.n})"></span>
          <span style="font-size:12.5px;font-weight:700;color:${on?lv.col:"var(--text-muted)"}">⚡ Level ${lv.n}</span>
        </label>
        <div style="${on?"":"opacity:.4;pointer-events:none"};display:flex;align-items:center;gap:5px;">
          <span style="font-size:12px;color:var(--text-muted)">after</span>
          <input id="snm-sec-l${lv.n}" type="number" style="width:65px" value="${lv.sec}" min="30"
            ${lv.n===1?'onchange="syncL1ToSnmWait()"':''}>
          <span style="font-size:12px;color:var(--text-muted)">sec</span>
        </div>
      </div>
      <div style="${on?"":"opacity:.4;pointer-events:none"};margin-top:8px;">
        <label style="font-size:11.5px;color:var(--text-secondary)">Level ${lv.n} emails (Cc)</label>
        <textarea id="snm-esc-l${lv.n}" rows="2" class="code-textarea" style="margin-top:3px"
          placeholder="email@corp.com">${fmtEmails(lv.emails)}</textarea>
        ${_renderEmailPickerInline("snm-esc-l"+lv.n,lv.emails)}
      </div>
      <div style="${on?"":"opacity:.4;pointer-events:none"};margin-top:8px;display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <div>
          <label style="font-size:11.5px;color:var(--text-secondary)">📱 SMS numbers <span style="color:var(--text-muted)">(V8.5)</span></label>
          <textarea id="snm-sms-l${lv.n}" rows="2" class="code-textarea" style="margin-top:3px"
            placeholder="+15551234567">${(lv.sms||[]).join("\n")}</textarea>
        </div>
        <div>
          <label style="font-size:11.5px;color:var(--text-secondary)">☎ Call numbers <span style="color:var(--text-muted)">(V8.5)</span></label>
          <textarea id="snm-call-l${lv.n}" rows="2" class="code-textarea" style="margin-top:3px"
            placeholder="+15551234567">${(lv.call||[]).join("\n")}</textarea>
        </div>
      </div>
    </div>`;
  }).join("");
}
function toggleSnmEsc(n){SNM_ESC["l"+n]=!SNM_ESC["l"+n];renderSnmEscLevels(window._snmCfg||{});}

const SNM_IDS={en:"snmt-en-",w:"snmt-w-",c:"snmt-c-",wait:"snmt-wait-"};
async function renderSnmThresholds(saved,deviceId,deviceWaitSec){
  deviceWaitSec = deviceWaitSec || 60;
  window._snmMetrics = null;
  const c=v("snm-thresholds"); if(!c) return;
  c.innerHTML='<div style="color:var(--text-muted);padding:8px">Loading metrics\u2026</div>';
  let _snmInh={inherit:{},sources:{}};
  try{ const ir=await fetch("/api/devices/"+encodeURIComponent(deviceId)+"/thresholds",{headers:authHeaders()}); if(ir.ok) _snmInh=ThrUI.inheritInfo(await ir.json()); }catch(_){}
  // The device's method decides which metrics are relevant (url = website -> response time, SSL, DNS ...)
  let method="ping";
  try{
    const r=await fetch("/api/devices",{headers:{"X-Session-Token":getSession()}});
    if(r.ok){const devs=await r.json();const d=devs.find(x=>x.id===deviceId);if(d)method=d.method||"ping";}
  }catch(_){}
  let meta;
  try{ meta=await ThrUI.load(); }
  catch(e){ c.innerHTML='<div style="color:var(--status-critical);padding:8px">Could not load the metric list ('+ThrUI.esc(e.message)+'). Close and reopen this window.</div>'; return; }
  const metrics=ThrUI.metricsFor(meta,method);
  window._snmMetrics=metrics;
  const title = method==="url" ? "Website thresholds" : "Device thresholds";
  c.innerHTML=`<div style="font-size:12px;color:var(--text-muted);margin-bottom:6px">${title}. Leave a box blank to use the global value (Settings &gt; Thresholds), then the recommended value shown in grey.</div>`+
    ThrUI.tableHTML(meta,metrics,saved,SNM_IDS,{wait:true,waitPlaceholder:deviceWaitSec,inherit:_snmInh.inherit,sources:_snmInh.sources})+
    `<div style="margin-top:8px"><button type="button" class="btn secondary small" onclick="snmFillRecommended()">Fill recommended values</button></div>`;
  snmRenderBars(deviceId);
}
function snmFillRecommended(){
  const meta=ThrUI.get(); if(!meta||!window._snmMetrics) return;
  ThrUI.fillRecommended(meta,window._snmMetrics,SNM_IDS);
}
async function saveSettNotifyModal(closeAfter){
  if (v("snm-trigger-mode")?.value === "sustained") syncSnmWaitToL1();
  const levels=SNM_ESC.l3?3:SNM_ESC.l2?2:SNM_ESC.l1?1:0;
  const getE=n=>{const t=v(`snm-esc-l${n}`);return t&&SNM_ESC["l"+n]?parseEmails(t.value):[];};
  const getS=n=>{const t=v(`snm-sec-l${n}`);return t?parseInt(t.value)||60:60;};
  // V8.5: same enabled-gating as getE (a disabled level's numbers aren't
  // sent, matching how its emails aren't either)
  const getSms=n=>{const t=v(`snm-sms-l${n}`);return t&&SNM_ESC["l"+n]?phoneListToArr(t.value):[];};
  const getCall=n=>{const t=v(`snm-call-l${n}`);return t&&SNM_ESC["l"+n]?phoneListToArr(t.value):[];};
  let thresholds=(window._snmCfg||{}).thresholds||{};     // table not rendered -> keep what is saved
  if(window._snmMetrics && ThrUI.get()){
    const res=ThrUI.collect(ThrUI.get(),window._snmMetrics,SNM_IDS,{wait:true});
    if(res.errors.length){ setStatus("snm-status",res.errors[0],false); return; }
    thresholds=res.thresholds;
  }
  const payload={
    notifications_enabled:v("snm-enabled")?.checked?1:0,
    notify_emails:parseEmails(v("snm-notify-emails")?.value||""),
    escalation_levels:levels,
    escalation_emails_l1:getE(1),escalation_emails_l2:getE(2),escalation_emails_l3:getE(3),
    escalation_after_sec_l1:getS(1),escalation_after_sec_l2:getS(2),escalation_after_sec_l3:getS(3),
    thresholds,
    alert_trigger_mode:v("snm-trigger-mode")?.value||"sustained",
    alert_notify_mode:v("snm-notify-mode")?.value||"immediate",
    notify_cooldown_sec:parseInt(v("snm-cooldown-sec")?.value)||300,
    sms_numbers_l1:getSms(1),sms_numbers_l2:getSms(2),sms_numbers_l3:getSms(3),
    call_numbers_l1:getCall(1),call_numbers_l2:getCall(2),call_numbers_l3:getCall(3),
  };
  const r=await fetch(`/api/devices/${encodeURIComponent(_snmDeviceId)}/notify`,{method:"POST",headers:authHeaders(),body:JSON.stringify(payload)});
  let _em="Save failed";
  if(!r.ok){ try{ const j=await r.json(); if(j&&j.error) _em=j.error; }catch(_){} }
  setStatus("snm-status",r.ok?"Saved ✓":_em,r.ok);
  if(r.ok){
    // V11.3 patch 08: refresh only the table you are looking at (the others reload when you open them), and close at once on "Save & close".
    reloadVisibleDeviceTable();
    if(closeAfter){ closeSettNotifyModal(); }
    else { ThrUI.resetContext(); renderSnmThresholds(payload.thresholds||{},_snmDeviceId,payload.escalation_after_sec_l1); }
  }
}
function closeSettNotifyModal(){v("sett-notify-modal")?.classList.add("hidden");}

/* ═══════════════════════════════════════════════════════════
   SMS & CALL ALERTS (V8.5)
═══════════════════════════════════════════════════════════ */
let _gatewayData = {sms: null, call: null};

async function loadSmsCallTab(){
  await Promise.all([_loadOneGateway("sms"), _loadOneGateway("call")]);
}

async function _loadOneGateway(kind){
  try{
    const r = await fetch(`/api/settings/${kind}-gateway`, {headers: authHeaders()});
    if(!r.ok) return;
    const d = await r.json();
    _gatewayData[kind] = d;

    v(`${kind}-enabled`).checked = !!d.enabled;
    v(`${kind}-method`).value    = d.method || "POST";
    v(`${kind}-url`).value       = d.url || "";
    v(`${kind}-headers`).value   = JSON.stringify(d.headers || {}, null, 2);
    v(`${kind}-body`).value      = d.body_template || "";
    v(`${kind}-auth`).value      = d.auth || "none";
    v(`${kind}-auth-user`).value = d.auth_user || "";
    v(`${kind}-auth-pass`).value = "";  // never pre-filled, matches SMTP's own pattern

    // Populate the preset dropdown from the server's own PRESETS registry
    // (messaging_gateway.py) rather than duplicating that list in JS --
    // one source of truth, so a new preset added server-side just shows
    // up here automatically.
    const sel = v(`${kind}-preset`);
    if(sel && d.preset_labels){
      sel.innerHTML = Object.entries(d.preset_labels)
        .map(([key,label]) => `<option value="${esc(key)}"${key===d.preset?" selected":""}>${esc(label)}</option>`)
        .join("");
    }
    _showPresetNote(kind, d.preset, d.preset_notes);
  }catch(e){}
}

function _showPresetNote(kind, presetKey, notes){
  const el = v(`${kind}-preset-note`);
  if(!el) return;
  const note = (notes || {})[presetKey];
  if(note){ el.textContent = note; el.style.display = "block"; }
  else { el.style.display = "none"; }
}

function applyGatewayPreset(kind){
  const presetKey = v(`${kind}-preset`)?.value;
  const d = _gatewayData[kind];
  if(!d || !d.presets || !d.presets[presetKey]) return;
  const p = d.presets[presetKey];
  v(`${kind}-method`).value  = p.method || "POST";
  v(`${kind}-url`).value     = p.url || "";
  v(`${kind}-headers`).value = JSON.stringify(p.headers || {}, null, 2);
  v(`${kind}-body`).value    = p.body_template || "";
  v(`${kind}-auth`).value    = p.auth || "none";
  _showPresetNote(kind, presetKey, d.preset_notes);
}

async function saveGateway(kind){
  let headers;
  try{ headers = JSON.parse(v(`${kind}-headers`).value || "{}"); }
  catch(e){ setStatus(`${kind}-status`, "Headers must be valid JSON", false); return; }

  const payload = {
    enabled: v(`${kind}-enabled`).checked,
    preset: v(`${kind}-preset`)?.value || "custom",
    method: v(`${kind}-method`).value,
    url: v(`${kind}-url`).value.trim(),
    headers,
    body_template: v(`${kind}-body`).value,
    auth: v(`${kind}-auth`).value,
    auth_user: v(`${kind}-auth-user`).value.trim(),
    auth_pass: v(`${kind}-auth-pass`).value,  // blank = keep existing, handled server-side
  };
  const r = await fetch(`/api/settings/${kind}-gateway`, {method:"POST", headers:authHeaders(), body:JSON.stringify(payload)});
  setStatus(`${kind}-status`, r.ok ? "Saved ✓" : "Save failed", r.ok);
  if(r.ok) _loadOneGateway(kind);
}

async function testGateway(kind){
  const phone = v(`${kind}-test-phone`)?.value.trim();
  if(!phone){ setStatus(`${kind}-status`, "Enter a phone number first", false); return; }
  setStatus(`${kind}-status`, "Sending…", true);
  const r = await fetch(`/api/settings/${kind}-gateway/test`, {method:"POST", headers:authHeaders(), body:JSON.stringify({phone})});
  const d = await r.json();
  setStatus(`${kind}-status`, d.ok ? "Test sent ✓ — check the device." : (d.error || "Test failed"), d.ok);
}

/* ═══════════════════════════════════════════════════════════
   ORGANISATION BRANDING (V8.5)
═══════════════════════════════════════════════════════════ */
let _pendingLogoDataUrl = null;

async function loadOrganisationTab(){
  try{
    const r = await fetch("/api/settings/organisation", {headers: authHeaders()});
    if(!r.ok) return;
    const d = await r.json();
    v("org-name").value = d.name || "";
    if(v("org-color")) v("org-color").value = d.color || "#8b95a5";
    _pendingLogoDataUrl = null;
    const preview = v("org-logo-preview"), img = v("org-logo-img");
    if(d.logo_path){
      img.src = d.logo_path + "?t=" + Date.now();  // cache-bust after a logo swap
      preview.style.display = "block";
    } else {
      preview.style.display = "none";
    }
  }catch(e){}
}

function _readLogoFile(){
  const fileInput = v("org-logo-file");
  const file = fileInput?.files?.[0];
  if(!file) { _pendingLogoDataUrl = null; return Promise.resolve(); }
  if(file.size > 2*1024*1024){
    setStatus("org-status", "Logo must be under 2MB", false);
    fileInput.value = "";
    return Promise.resolve();
  }
  return new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = () => { _pendingLogoDataUrl = reader.result; resolve(); };
    reader.readAsDataURL(file);
  });
}

async function saveOrganisation(){
  await _readLogoFile();
  setStatus("org-status", "Saving…", true);

  const r1 = await fetch("/api/settings/organisation", {
    method:"POST", headers:authHeaders(), body:JSON.stringify({name: v("org-name").value.trim(), color: v("org-color")?.value || "#8b95a5"})
  });
  let ok = r1.ok, msg = ok ? "Saved ✓" : "Save failed";

  if(_pendingLogoDataUrl){
    const r2 = await fetch("/api/settings/organisation/logo", {
      method:"POST", headers:authHeaders(), body:JSON.stringify({logo_data: _pendingLogoDataUrl})
    });
    const d2 = await r2.json();
    ok = ok && r2.ok;
    msg = r2.ok ? "Saved ✓" : (d2.error || "Logo upload failed");
  }
  setStatus("org-status", msg, ok);
  if(ok){
    v("org-logo-file").value = "";
    loadOrganisationTab();
    // Refresh the sidebar branding immediately, without a full page reload
    location.reload();
  }
}

async function removeOrgLogo(){
  if(!confirm("Remove the organisation logo? The name (if set) will still show.")) return;
  const r = await fetch("/api/settings/organisation/logo", {method:"DELETE", headers:authHeaders()});
  if(r.ok){ loadOrganisationTab(); location.reload(); }
}

/* ═══════════════════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════════════════ */
function initAll(){
  loadSmtp();
  setInterval(()=>{if(document.getElementById("tab-alerts")?.classList.contains("active"))loadAlerts();},15000);
  setInterval(()=>{if(document.getElementById("tab-audit")?.classList.contains("active"))loadAuditLog();},20000);
}
document.addEventListener("DOMContentLoaded",()=>{
  document.querySelectorAll(".stab").forEach(btn=>btn.addEventListener("click",()=>switchTab(btn.dataset.tab)));
  v("btn-save-smtp")       ?.addEventListener("click",saveSmtp);
  v("btn-test-warn")       ?.addEventListener("click",()=>testEmail("warning"));
  v("btn-test-crit")       ?.addEventListener("click",()=>testEmail("critical"));
  v("btn-save-notif")      ?.addEventListener("click",saveNotif);
  v("btn-save-esc-global") ?.addEventListener("click",saveEscGlobal);
  v("btn-apply-esc-all")   ?.addEventListener("click",applyEscToAll);
  v("su-token")            ?.addEventListener("input",suCheckToken);
  v("btn-sett-add-device") ?.addEventListener("click",settingsAddDevice);
  v("qd-method")           ?.addEventListener("change",renderQdMethodFields);
  v("org-logo-file")       ?.addEventListener("change",_readLogoFile);
  checkAccess();
});

// V11.3 patch 06: Settings notify window "apply to ..." bars + the Escalation tab's "Current search / filter" button.
/* V11.3 patch 08: every device's notification settings in ONE request. The Notifications / Escalation / Thresholds tables used to
   ask for them one device at a time (the Notifications table one AFTER another), and ran after every save. */
async function getNotifyMap(devices){
  try{
    const r=await fetch("/api/devices/notify-all",{headers:{"X-Session-Token":getSession()}});
    if(r.ok){ const j=await r.json(); if(j&&j.notify) return j.notify; }
  }catch(_){}
  const m={};   // older server without the bulk call
  await Promise.all(devices.map(async d=>{ try{ const nr=await fetch(`/api/devices/${encodeURIComponent(d.id)}/notify`,{headers:{"X-Session-Token":getSession()}}); if(nr.ok) m[d.id]=await nr.json(); }catch(_){} }));
  return m;
}
function reloadVisibleDeviceTable(){
  const pane=[...document.querySelectorAll('[id^="tab-"]')].find(p=>p.offsetParent!==null && p.querySelector("[data-mon-id]"));
  const id=pane?pane.id:"";
  if(id==="tab-escalation") loadEscDeviceTable();
  else if(id==="tab-thresholds") loadThreshDeviceTable();
  else if(id==="tab-notifications") loadNotifDeviceTable();
  else if(id==="tab-devices") loadDevicesTab();   // the other tables reload when their tab is opened
}
let _snmTargets=[];
function settVisibleIds(){
  const pane=[...document.querySelectorAll('[id^="tab-"]')].find(p=>p.offsetParent!==null && p.querySelector("[data-mon-id]"));
  if(!pane) return [];
  return [...pane.querySelectorAll("[data-mon-id]")].filter(r=>r.style.display!=="none" && r.offsetParent!==null).map(r=>r.getAttribute("data-mon-id"));
}
async function snmRenderBars(deviceId){
  const tb=v("snm-apply-timing"), hb=v("snm-apply-thr");
  if(tb) tb.innerHTML=""; if(hb) hb.innerHTML="";
  let ctx; try{ ThrUI.resetContext(); ctx=await ThrUI.context(deviceId); }catch(e){ return; }
  if(deviceId!==_snmDeviceId) return;
  const fi=settVisibleIds(), narrowed=fi.length>0 && fi.length<(ctx.facets.methods||[]).reduce((n,x)=>n+(x.count||0),0);
  _snmTargets=ThrUI.targets(ctx.dev,ctx.facets,narrowed?fi:null,{methods:ctx.methodOf});
  if(tb) tb.innerHTML=ThrUI.barHTML("Apply wait & cooldown to:",_snmTargets,"snmApplyTiming");
  if(hb) hb.innerHTML=ThrUI.barHTML("Apply the thresholds above to:",_snmTargets,"snmApplyThr");
}
async function snmApplyTiming(key){
  const t=_snmTargets.find(x=>x.key===key); if(!t) return;
  try{ const res=await ThrUI.applyTiming(t,"snm"); if(res.cancelled) return; showToast(res.message,res.ok?"success":"error"); if(res.ok) ThrUI.resetContext(); }
  catch(e){ showToast("Apply failed: "+e.message,"error"); }
}
async function snmApplyThr(key){
  const t=_snmTargets.find(x=>x.key===key); if(!t) return;
  if(!window._snmMetrics||!ThrUI.get()){ showToast("The threshold table is not loaded yet.","error"); return; }
  const col=ThrUI.collect(ThrUI.get(),window._snmMetrics,SNM_IDS,{wait:true});
  if(col.errors.length){ showToast(col.errors[0],"error"); return; }
  try{ const res=await ThrUI.applyThr(t,col.thresholds); if(res.cancelled) return; showToast(res.message,res.ok?"success":"error");
    if(res.ok){ reloadVisibleDeviceTable(); const c=await (await fetch("/api/devices/"+encodeURIComponent(_snmDeviceId)+"/notify",{headers:authHeaders()})).json(); renderSnmThresholds(c.thresholds||{},_snmDeviceId,c.escalation_after_sec_l1); } }
  catch(e){ showToast("Apply failed: "+e.message,"error"); }
}
async function applyEscFilter(){
  const ids=settVisibleIds();
  if(!ids.length){ showToast("No monitors are showing. Clear or change the search / filter first.","error"); return; }
  try{
    const res=await ThrUI.applyTiming({key:"filter",label:"the monitors in your current search / filter",count:ids.length,body:{ids}},"esc-g");
    if(res.cancelled) return; showToast(res.message,res.ok?"success":"error"); if(res.ok){ loadEscDeviceTable(); }
  }catch(e){ showToast("Apply failed: "+e.message,"error"); }
}

// V11.2: "Apply wait & cooldown to ..." buttons (Escalation tab, notify windows). prefix = id prefix of the 4 timing fields.
async function applyTimingBtn(scope, prefix){
  try{
    const res=await ThrUI.applyTiming(scope,prefix);
    if(res.cancelled) return;
    showToast(res.message, res.ok?"success":"error");
    if(res.ok){ loadEscDeviceTable(); }
  }catch(e){ showToast("Apply failed: "+e.message,"error"); }
}

// V11.3 patch 03: Offline detection settings (Escalation tab)
async function loadOfflineDetection(){
  try{
    const r=await fetch("/api/settings/offline-detection",{headers:{"X-Session-Token":getSession()}});
    if(!r.ok) return; const d=await r.json();
    const set=(id,val)=>{ const e=v(id); if(e) e.value=val; };
    set("od-retries",d.offline_retries); set("od-delay",d.offline_retry_delay_sec); set("od-confirm",d.offline_confirm_polls);
  }catch(_){}
}
async function saveOfflineDetection(){
  const num=(id)=>parseInt((v(id)||{}).value);
  const body={offline_retries:num("od-retries"),offline_retry_delay_sec:num("od-delay"),offline_confirm_polls:num("od-confirm")};
  try{
    const r=await fetch("/api/settings/offline-detection",{method:"POST",headers:authHeaders(),body:JSON.stringify(body)});
    let j={}; try{ j=await r.json(); }catch(_){}
    if(!r.ok||!j.ok){ setStatus("od-status",(j&&j.error)||("Save failed ("+r.status+")"),false); return; }
    setStatus("od-status","Saved \u2713 \u2014 applies from the next check",true);
  }catch(e){ setStatus("od-status","Save failed: "+e.message,false); }
}

/* ═══════════════════════════════════════════════════════════
   V11.3 patch 04 -- thresholds for a TYPE (firewalls, switches, servers ...) or a METHOD (ping, SSH, shared folders ...)
   Priority, low to high: All devices < method < type < the monitor's own values.
   ═══════════════════════════════════════════════════════════ */
const SC_IDS={en:"sc-en-",w:"sc-w-",c:"sc-c-"};
function _scState(){ return (globalThis._thrScoped=globalThis._thrScoped||{type:{},method:{}}); }
function thrScope(){
  const val=(v("thr-scope")||{}).value||"all"; if(val==="all"||!val) return {kind:"all",key:""};
  const i=val.indexOf(":"); return {kind:val.slice(0,i),key:val.slice(i+1)};
}
// Metrics offered for a scope: a METHOD -> what that method produces; a TYPE -> what its devices can report (from the
// server: the methods those devices use). Never "everything".
function scopeKeys(sc,meta){
  if(sc.kind==="method") return meta.methods[sc.key]||meta.device_metrics;
  const f=(globalThis._thrFacets||{}), row=(f.types||[]).find(t=>t.id===sc.key)||(f.all_types||[]).find(t=>t.id===sc.key);
  return (row&&row.metrics&&row.metrics.length)?row.metrics:meta.device_metrics;
}
function scopeBasis(sc){
  if(sc.kind==="method") return "Shows only what "+scopeLabel(sc)+" can measure.";
  const f=(globalThis._thrFacets||{}), row=(f.types||[]).find(t=>t.id===sc.key);
  const ms=(row&&row.methods||[]).map(m=>MonFilter.METHOD_LABELS[m]||m);
  return ms.length?("Shows what "+scopeLabel(sc)+" devices report: they are checked by "+ms.join(", ")+".")
                  :("No "+scopeLabel(sc)+" device exists yet, so this shows the usual metrics for the type.");
}
function scopeLabel(sc){
  if(sc.kind==="type") return MonFilter.TYPE_LABELS[sc.key]||sc.key;
  if(sc.kind==="method") return MonFilter.METHOD_LABELS[sc.key]||sc.key;
  return "All devices";
}
async function loadScopedThresholds(){
  try{
    const r=await fetch("/api/settings/thresholds/scoped",{headers:{"X-Session-Token":getSession()}});
    if(r.ok){ const d=await r.json(); globalThis._thrScoped={type:d.type||{},method:d.method||{}}; }
  }catch(_){}
  await renderScopeSelect();
}
async function renderScopeSelect(){
  const sel=v("thr-scope"); if(!sel) return;
  const facets=await MonFilter.loadFacets(true), keep=sel.value||"all", sc=_scState();
  globalThis._thrFacets=facets;
  const mark=(kind,key)=>Object.keys(sc[kind][key]||{}).length?" \u2713 custom":"";
  let h='<option value="all">All devices</option>';
  const types=(facets.types||[]).slice();
  Object.keys(sc.type).forEach(k=>{ if(!types.some(t=>t.id===k)) types.push({id:k,label:MonFilter.TYPE_LABELS[k]||k,count:0}); });
  h+='<optgroup label="By type">'+types.map(t=>`<option value="type:${esc(t.id)}">${esc(t.label)} (${t.count})${mark("type",t.id)}</option>`).join("")+"</optgroup>";
  const methods=(facets.methods||[]).filter(m=>m.id!=="url");
  h+='<optgroup label="By method">'+methods.map(m=>`<option value="method:${esc(m.id)}">${esc(m.label)} (${m.count})${mark("method",m.id)}</option>`).join("")+"</optgroup>";
  sel.innerHTML=h; sel.value=[...sel.options].some(o=>o.value===keep)?keep:"all";
  onThrScope();
}
function syncThrFilter(){
  const sc=thrScope();
  MonFilter.set("mf-thr",{type:sc.kind==="type"?sc.key:"",method:sc.kind==="method"?sc.key:""});
}
function onThrScope(){
  const sc=thrScope(), root=v("thr-root");
  if(root) root.setAttribute("data-dscope",sc.kind==="all"?"all":"scoped");
  renderScopedTable(); syncThrFilter();
}
function renderScopedTable(){
  const wrap=v("scoped-thresh-wrap"); if(!wrap) return;
  const sc=thrScope(), meta=ThrUI.get();
  if(sc.kind==="all"||!meta){ wrap.innerHTML=""; return; }
  const keys=scopeKeys(sc,meta);
  const saved=(_scState()[sc.kind]||{})[sc.key]||{};
  const inherit={}; keys.forEach(k=>{ const g=_globalThresh[k]||{}, m=meta.metrics[k]; inherit[k]={warning:g.warning!=null?g.warning:m.warning,critical:g.critical!=null?g.critical:m.critical}; });
  const label=scopeLabel(sc), noun=sc.kind==="type"?"every "+label+" device":"every device checked by "+label;
  wrap.innerHTML=`<div class="thr-sec" data-scope="devices-scoped">
    <h3 style="font-size:15px;margin:2px 0 2px">${esc(label)} thresholds</h3>
    <p style="font-size:12px;color:var(--text-muted);margin:0 0 4px">Applies to ${esc(noun)}. ${esc(scopeBasis(sc))}</p>
    <p style="font-size:12px;color:var(--text-muted);margin:0 0 8px"><strong>Leave a box empty to inherit</strong> the grey value (from All devices). Hover or click the <span class="thr-i" style="pointer-events:none">!</span> for details.</p>
    <div style="overflow-x:auto">${ThrUI.tableHTML(meta,keys,saved,SC_IDS,{wait:false,inherit})}</div>
    <div class="thr-actions">
      <button type="button" class="btn primary" id="btn-save-scope" onclick="saveScoped(false)">Save ${esc(label)} thresholds</button>
      <button type="button" class="btn secondary" id="btn-apply-scope" onclick="saveScoped(true)">Apply to all ${esc(label)}</button>
      <button type="button" class="btn secondary" id="btn-clear-scope" onclick="clearScoped()">Clear (inherit All devices)</button>
      <button type="button" class="btn secondary" id="btn-fill-scope" onclick="fillScoped()">Fill recommended values</button>
    </div>
    <p style="font-size:12px;color:var(--text-muted);margin:6px 0 0"><strong>Save</strong> keeps these for the group. <strong>Apply to all</strong> also removes any monitor's own value of these metrics inside the group. <strong>Clear</strong> removes this group's thresholds.</p>
  </div>`;
}
async function saveScoped(apply){
  const meta=ThrUI.get(), sc=thrScope();
  if(!meta||sc.kind==="all"){ setStatus("s-thresh-status","Choose a type or a method first",false); return; }
  const keys=scopeKeys(sc,meta);
  const {thresholds,errors}=ThrUI.collect(meta,keys,SC_IDS,{wait:false});
  if(errors.length){ setStatus("s-thresh-status",errors[0],false); return; }
  const body={kind:sc.kind,key:sc.key,thresholds:ThrUI.compact(thresholds),apply:!!apply};
  if(apply&&!Object.keys(body.thresholds).length){ setStatus("s-thresh-status","Nothing to apply: fill at least one value first",false); return; }
  if(apply&&!confirm("Apply these thresholds to ALL "+scopeLabel(sc)+" monitors?\n\nAny monitor's own value of these metrics is removed, so they all follow this group. Wait times are kept.")) return;
  const r=await fetch("/api/settings/thresholds/scoped",{method:"POST",headers:authHeaders(),body:JSON.stringify(body)});
  let j={}; try{ j=await r.json(); }catch(_){}
  if(!r.ok||!j.ok){ setStatus("s-thresh-status",(j&&j.error)||("Save failed ("+r.status+")"),false); return; }
  setStatus("s-thresh-status",(apply?"Applied to "+j.count+" monitor"+(j.count===1?"":"s")+" \u2713 ("+j.overrides_removed+" own value"+(j.overrides_removed===1?"":"s")+" removed)":"Saved \u2713 ("+j.count+" monitor"+(j.count===1?"":"s")+" in this group)"),true);
  await loadScopedThresholds(); loadThreshDeviceTable();
}
async function clearScoped(){
  const sc=thrScope(); if(sc.kind==="all") return;
  if(!confirm("Remove the "+scopeLabel(sc)+" thresholds? Those monitors go back to the All devices values.")) return;
  const r=await fetch("/api/settings/thresholds/scoped",{method:"POST",headers:authHeaders(),body:JSON.stringify({kind:sc.kind,key:sc.key,thresholds:{}})});
  let j={}; try{ j=await r.json(); }catch(_){}
  if(!r.ok||!j.ok){ setStatus("s-thresh-status",(j&&j.error)||("Clear failed ("+r.status+")"),false); return; }
  setStatus("s-thresh-status","Cleared \u2713 \u2014 "+scopeLabel(sc)+" now inherits All devices",true);
  await loadScopedThresholds(); loadThreshDeviceTable();
}
function fillScoped(){
  const meta=ThrUI.get(), sc=thrScope(); if(!meta||sc.kind==="all") return;
  const keys=scopeKeys(sc,meta);
  ThrUI.fillRecommended(meta,keys,SC_IDS);
  setStatus("s-thresh-status","Filled with the recommended values \u2014 click Save to keep them",true);
}
