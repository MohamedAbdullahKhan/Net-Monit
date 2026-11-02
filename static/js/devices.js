/* =============================================================================
 * Net-monit V11.3
 * Copyright (c) 2024-2026 Abdullah. All rights reserved.
 * Contact: abuabdullah.be@outlook.com
 * ============================================================================= */
/* devices.js — V3.5
   FIXES:
   #5  PowerShell credentials fields shown correctly
   #6  Escalation: existing receivers pre-checked; + / − buttons to add/remove from predefined list
   #7  Per-metric enabled checkbox persists correctly; notify emails shown who already receive alerts
   #9  Test device button — calls /api/devices/<id>/test, shows pass/fail with detail
*/

const METHOD_FIELDS = {
  ping: [],
  snmp: [
    {id:"snmp-community", label:"Community string", placeholder:"public"},
    {id:"snmp-version",   label:"SNMP version",     placeholder:"2", type:"number"},
  ],
  powershell: [
    {id:"ps-remote",   label:"Remote monitoring",         type:"select",   opts:["false:Local (this machine runs PS)","true:Remote (WinRM)"]},
    {id:"ps-username", label:"Username (DOMAIN\\\\user)", placeholder:"DOMAIN\\\\username"},
    {id:"ps-password", label:"Password",                   placeholder:"", type:"password"},
  ],
  ssh: [
    {id:"ssh-port",     label:"Port",                   placeholder:"22", type:"number"},
    {id:"ssh-username", label:"Username",               placeholder:"monitor"},
    {id:"ssh-password", label:"Password",               placeholder:"", type:"password"},
    {id:"ssh-keypath",  label:"Key path (optional)",    placeholder:"/home/user/.ssh/id_rsa"},
  ],
  disk_usage: [
    {id:"disk-os",       label:"OS (windows/linux)",   placeholder:"windows"},
    {id:"disk-path",     label:"Path (UNC or mount)",  placeholder:"\\\\server\\share", wide:true},
    {id:"disk-username", label:"Username",             placeholder:""},
    {id:"disk-password", label:"Password",             placeholder:"", type:"password"},
  ],
};

// V11.1: metric names, units, ranges and recommended values come from the server (/api/threshold-meta) and are
// rendered by static/js/threshold_ui.js (ThrUI). The old hard-coded six-metric copies lived here.

function esc(s){ return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
function val(id){ const e=document.getElementById(id); return e?e.value.trim():""; }
function emailListToArr(text){ return text.split(/[,\n]+/).map(s=>s.trim()).filter(Boolean); }
function arrToEmailList(arr){ return (arr||[]).join("\n"); }
// V8.5: same split/trim pattern as emails, for phone numbers -- kept as
// a separate named function (not just reused emailListToArr) so intent
// is clear at each call site and either one's parsing rules can diverge
// later (e.g. phone number format validation) without touching the other.
function phoneListToArr(text){ return text.split(/[,\n]+/).map(s=>s.trim()).filter(Boolean); }

// ── Method-specific extra fields ───────────────────────────────────────────
const DEV_METHOD_METRICS = {
  ping:       [{id:"latency_ms",label:"Latency (ms)",chk:true},{id:"packet_loss_pct",label:"Packet Loss (%)",chk:true}],
  snmp:       [{id:"latency_ms",label:"Latency",chk:true},{id:"packet_loss_pct",label:"Packet Loss",chk:true},{id:"cpu_pct",label:"CPU %",chk:true},{id:"bandwidth_pct",label:"Bandwidth %",chk:true}],
  powershell: [{id:"latency_ms",label:"Latency",chk:true},{id:"packet_loss_pct",label:"Packet Loss",chk:true},{id:"cpu_pct",label:"CPU %",chk:true},{id:"memory_pct",label:"Memory %",chk:true},{id:"disk_pct",label:"Disk %",chk:true},{id:"bandwidth_pct",label:"Bandwidth %",chk:false}],
  ssh:        [{id:"latency_ms",label:"Latency",chk:true},{id:"packet_loss_pct",label:"Packet Loss",chk:true},{id:"cpu_pct",label:"CPU %",chk:true},{id:"memory_pct",label:"Memory %",chk:true},{id:"disk_pct",label:"Disk %",chk:true}],
  disk_usage: [{id:"disk_pct",label:"Disk %",chk:true},{id:"latency_ms",label:"Latency",chk:true}],
};

function renderMethodFields(){
  const m = document.getElementById("f-method").value;
  const fields = METHOD_FIELDS[m] || [];
  const c = document.getElementById("method-fields");
  // Render metric checkboxes
  const mc = document.getElementById("method-metrics");
  const metrics = DEV_METHOD_METRICS[m]||[];
  if(mc && metrics.length){
    mc.innerHTML=`<div style="padding:10px;border:1px solid var(--border);border-radius:var(--radius-sm);background:rgba(255,255,255,.02);">
      <p style="font-size:11.5px;color:var(--text-muted);margin-bottom:7px;">📊 Metrics to monitor:</p>
      <div style="display:flex;flex-wrap:wrap;gap:6px;">
        ${metrics.map(mt=>`<label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;
          padding:3px 9px;border-radius:4px;border:1px solid var(--border);background:var(--bg-hover);">
          <input type="checkbox" id="fm-${mt.id}" ${mt.chk?"checked":""}> ${mt.label}</label>`).join("")}
      </div></div>`;
  } else if(mc){ mc.innerHTML=""; }
  if(!fields.length){ c.innerHTML=""; } else {
  c.innerHTML=`<div class="form-grid">${fields.map(f=>{
    if(f.type==="select"){
      return `<div class="field" style="${f.wide?"grid-column:1/-1;":""}">
        <label>${f.label}</label>
        <select id="${f.id}">${f.opts.map(o=>{const[v,l]=o.split(":");return`<option value="${v}">${l}</option>`;}).join("")}</select></div>`;
    }
    return `<div class="field" style="${f.wide?"grid-column:1/-1;":""}">
      <label>${f.label}</label>
      <input id="${f.id}" type="${f.type||"text"}" placeholder="${f.placeholder||""}"></div>`;
  }).join("")}</div>`;
  }
  // V8.2: services/tasks watching -- only offered for methods that already
  // collect ssh/powershell credentials above, since it reuses those same
  // credentials rather than asking a second time.
  const stc = document.getElementById("method-services-tasks");
  if(!stc) return;
  if(m!=="ssh" && m!=="powershell"){ stc.innerHTML=""; return; }
  const platform = m==="powershell" ? "windows" : "linux";
  const svcHint  = platform==="windows" ? "Spooler, wuauserv" : "sshd, nginx, docker";
  const taskHint = platform==="windows" ? "\\Backup\\NightlyBackup" : "backup (systemd timer)";
  stc.innerHTML = `
    <div style="border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;margin-top:2px;">
      <p style="font-size:12px;font-weight:600;margin-bottom:8px;">🩺 Watch services / scheduled tasks on this host (optional)</p>
      <div class="form-grid">
        <div class="field">
          <label style="display:flex;align-items:center;gap:7px;cursor:pointer;">
            <input type="checkbox" id="svc-watch-enabled"> Watch services</label>
          <textarea id="svc-watch-items" rows="2" class="code-textarea" style="margin-top:6px;"
            placeholder="One per line, e.g.\n${svcHint}"></textarea>
        </div>
        <div class="field">
          <label style="display:flex;align-items:center;gap:7px;cursor:pointer;">
            <input type="checkbox" id="task-watch-enabled"> Watch scheduled tasks</label>
          <textarea id="task-watch-items" rows="2" class="code-textarea" style="margin-top:6px;"
            placeholder="One per line, e.g.\n${taskHint}"></textarea>
        </div>
      </div>
      <p style="font-size:11px;color:var(--text-muted);margin-top:6px;">
        Any watched item that's stopped / failed marks this device Critical. Uses the ${m==="powershell"?"PowerShell":"SSH"} credentials above.
      </p>
    </div>`;
}

// ── Build device payload ───────────────────────────────────────────────────
function buildDevice(){
  const m = val("f-method");
  const d = {id:val("f-id"), name:val("f-name"), host:val("f-host"), type:val("f-type"), method:m};
  const iv = val("f-interval"); if(iv) d.poll_interval_seconds = parseInt(iv);
  if(m==="snmp")
    d.snmp = {community:val("snmp-community")||"public", version:parseInt(val("snmp-version")||"2")};
  else if(m==="powershell"){
    const remote = (() => { const el = document.getElementById("ps-remote"); return el ? el.value === "true" : false; })();
    d.powershell = {remote, use_winrm:true, username:val("ps-username")||null, password:val("ps-password")||null};
    if(!d.powershell.username) delete d.powershell.username;
    if(!d.powershell.password) delete d.powershell.password;
  } else if(m==="ssh")
    d.ssh = {port:parseInt(val("ssh-port")||"22"), username:val("ssh-username")||"monitor", password:val("ssh-password")||null, key_path:val("ssh-keypath")||null};
  else if(m==="disk_usage")
    d.disk = {os:val("disk-os")||"windows", path:val("disk-path"), remote:true, username:val("disk-username")||null, password:val("disk-password")||null};
  // V8.2: services/tasks watching (ssh/powershell devices only)
  if(m==="ssh" || m==="powershell"){
    const platform = m==="powershell" ? "windows" : "linux";
    const svcEn  = document.getElementById("svc-watch-enabled")?.checked || false;
    const svcTxt = document.getElementById("svc-watch-items")?.value || "";
    const taskEn  = document.getElementById("task-watch-enabled")?.checked || false;
    const taskTxt = document.getElementById("task-watch-items")?.value || "";
    d.services_watch = {enabled:svcEn, platform, items:svcTxt.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean)};
    d.tasks_watch    = {enabled:taskEn, platform, items:taskTxt.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean)};
  }
  return d;
}

// ── Add / update device ────────────────────────────────────────────────────
async function addDevice(){
  const device  = buildDevice();
  if(!device.id||!device.name||!device.host){ showToast("ID, name, host required","error"); return; }
  const isEdit  = !!_editDeviceId;
  const url     = isEdit ? `/api/devices/${encodeURIComponent(_editDeviceId)}` : "/api/devices";
  const method  = isEdit ? "PUT" : "POST";
  if(isEdit){
    if(device.powershell&&!device.powershell.password) delete device.powershell.password;
    if(device.ssh&&!device.ssh.password)               delete device.ssh.password;
    if(device.disk&&!device.disk.password)             delete device.disk.password;
  }
  const r = await fetch(url,{method, headers:authHeaders(), body:JSON.stringify(device)});
  if(r.ok){
    // "Show on Dashboard" checkbox -- new devices default to visible on the
    // server already, so we only need to act when the box was UNCHECKED.
    const showBox = document.getElementById("f-show-dashboard");
    if (showBox) {
      try {
        await fetch(`/api/tiles/${encodeURIComponent(device.id)}/${showBox.checked ? "show" : "hide"}`,
          { method: "POST", headers: authHeaders() });
      } catch(_) {}
    }
    showToast(isEdit?`${device.name} updated`:`${device.name} added`,"success");
    cancelEdit();
    loadDevices();
  } else {
    const d = await r.json();
    showToast(d.error||"Failed","error");
  }
}

function cancelEdit(){
  _editDeviceId = null;
  document.getElementById("f-id").disabled = false;
  document.getElementById("add-device-card").querySelector(".card-title").textContent = "Add device / server / shared drive";
  document.getElementById("btn-add-device").textContent = "Add device";
  document.getElementById("btn-cancel-edit").style.display = "none";
  ["f-id","f-name","f-host","f-interval"].forEach(id=>{ const el=document.getElementById(id); if(el) el.value=""; });
  document.getElementById("method-fields").innerHTML="";
}

async function deleteDevice(id, name){
  if(!confirm(`Permanently remove "${name}"?\n\nThis stops monitoring and clears all history.\nTo just hide from dashboard, use the tile menu (… button) → Hide tile.`)) return;
  const r = await fetch(`/api/devices/${encodeURIComponent(id)}`,{method:"DELETE",headers:authHeaders()});
  if(r.ok){ showToast(`${name} removed`,"success"); loadDevices(); }
  else showToast("Failed","error");
}

// ── FIX #9: Test device ────────────────────────────────────────────────────
async function testDevice(id, name){
  const btn = document.getElementById(`test-btn-${id}`);
  const res = document.getElementById(`test-result-${id}`);
  if(btn){ btn.disabled=true; btn.textContent="Testing…"; }
  if(res){ res.textContent=""; res.className=""; }
  try{
    const r = await fetch(`/api/devices/${encodeURIComponent(id)}/test`,{method:"POST",headers:authHeaders()});
    const d = await r.json();
    if(res){
      res.textContent = d.ok ? `✔ PASS — ${d.detail}` : `✖ FAIL — ${d.detail}`;
      res.style.color = d.ok ? "var(--status-ok)" : "var(--status-critical)";
      res.style.fontSize = "12px";
    }
    showToast(d.ok ? `${name}: Test PASS` : `${name}: Test FAIL — ${d.detail}`, d.ok?"success":"error");
  } catch(e){
    if(res){ res.textContent="Error: "+e.message; res.style.color="var(--status-critical)"; }
  } finally {
    if(btn){ btn.disabled=false; btn.textContent="Test"; }
  }
}

// ── Credential hint ────────────────────────────────────────────────────────
function credHint(d){
  const fields = {powershell:d.powershell?.password, ssh:d.ssh?.password, disk_usage:d.disk?.password};
  const pw = fields[d.method];
  if(!pw) return "";
  const enc = pw && pw.startsWith("ENC:");
  return `<span style="font-size:10.6px;color:${enc?"var(--status-ok)":"var(--status-warning)"};margin-top:2px;display:block;">
    ${enc?"🔒 Credentials encrypted":"⚠ Credentials stored as plain text — re-save to encrypt"}
  </span>`;
}

// ── Device list ────────────────────────────────────────────────────────────
const TYPE_ICONS = {
  network:"🌐", router:"🧭", switch:"🔀", firewall:"🛡", wireless:"📡", windows:"🖥", linux:"🐧",
  vmware:"⚙", nas:"💾", printer:"🖨", ups:"⚡", camera:"📷", other:"📦",
};

async function loadDevices(){
  const r = await fetch("/api/devices",{headers:{"X-Session-Token":getSession()}});
  const allDevices = await r.json();
  setTimeout(() => _openFromHash(allDevices), 0);
  window._devMethods = {}; allDevices.forEach(d => { window._devMethods[d.id] = d.method || "ping"; });
  // URL/site devices are managed exclusively on the Sites Monitor page --
  // keep the Devices page focused on hardware/network devices only.
  const devices = allDevices.filter(d => (d.method || "") !== "url");
  document.getElementById("device-count").textContent = `${devices.length} device(s) configured`;
  _devList = devices;
  const sel = document.getElementById("dev-group"); if(sel) sel.value = _devGroup();
  renderDeviceList();
}

// V11.3 patch 05: Devices page -- filter by type / method and optional grouping, same bar as Settings
let _devList = [];
function _devGroup(){ try{ const g = sessionStorage.getItem("dev-group"); return (g==="type"||g==="method") ? g : "none"; }catch(_){ return "none"; } }
function setDevGroup(g){ try{ sessionStorage.setItem("dev-group", g); }catch(_){} renderDeviceList(); }

function _deviceRowHTML(d, isAdm){
  return `
    <div class="device-list-row" ${MonFilter.attrs(d)}>
      <div class="device-list-meta">
        <span class="device-type-badge" title="${esc(d.type)}">${TYPE_ICONS[d.type]||"?"} ${esc(MonFilter.METHOD_LABELS[d.method]||d.method)}</span>
        <div>
          <div style="font-weight:600;">${esc(d.name)}</div>
          <div class="device-host">${esc(d.host||"***")}${d.disk&&d.disk.path?" · "+esc(d.disk.path):""}</div>
          <div style="font-size:11px;color:var(--text-muted);">${esc(MonFilter.TYPE_LABELS[d.type]||d.type||"")}${d.poll_interval_seconds?" · poll every "+d.poll_interval_seconds+"s":""}</div>
          ${credHint(d)}
          <div id="test-result-${esc(d.id)}" style="margin-top:3px;"></div>
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        ${isAdm?`<button id="test-btn-${esc(d.id)}" class="btn secondary small" onclick="testDevice('${esc(d.id)}','${esc(d.name)}')">&#9654; Test</button>`:""}
        <button class="btn secondary small" onclick="openNotifyModal('${esc(d.id)}','${esc(d.name)}')" title="Notification & escalation settings">&#9993; Notify</button>
        ${isAdm?`<button class="btn secondary small" onclick='openEditModal(${JSON.stringify(JSON.stringify(d))})'>&#9998; Edit</button>`:""}
        ${isAdm?`<button class="btn danger small" onclick="deleteDevice('${esc(d.id)}','${esc(d.name)}')">Remove</button>`:""}
      </div>
    </div>`;
}

function renderDeviceList(){
  const list = document.getElementById("device-list"); if(!list) return;
  const isAdm = !!getSession(), g = _devGroup();
  if(!_devList.length){ list.innerHTML = `<p class="card-sub">No devices yet. (Web/URL sites are managed on the Sites Monitor page.)</p>`; return; }
  if(g === "none"){ list.innerHTML = _devList.map(d => _deviceRowHTML(d, isAdm)).join(""); }
  else {
    const labels = g === "type" ? MonFilter.TYPE_LABELS : MonFilter.METHOD_LABELS, groups = {};
    _devList.forEach(d => { const k = d[g] || "other"; (groups[k] = groups[k] || []).push(d); });
    list.innerHTML = Object.keys(groups).sort((a,b) => String(labels[a]||a).localeCompare(String(labels[b]||b))).map(k =>
      `<section class="dev-group" data-mon-box><h3 class="dev-group-h">${esc(labels[k]||k)} <span>(${groups[k].length})</span></h3>${groups[k].map(d => _deviceRowHTML(d, isAdm)).join("")}</section>`).join("");
  }
  MonFilter.mount("mf-dev", "device-list");
}

// ── Edit modal ─────────────────────────────────────────────────────────────
let _editDeviceId = null;

function openEditModal(deviceJsonStr){
  try{
    const d = JSON.parse(deviceJsonStr);
    _editDeviceId = d.id;
    document.getElementById("f-id").value     = d.id;
    document.getElementById("f-id").disabled  = true;
    document.getElementById("f-name").value   = d.name||"";
    document.getElementById("f-host").value   = d.host==="***"?"":d.host||"";
    document.getElementById("f-type").value   = d.type||"network";
    document.getElementById("f-method").value = d.method||"ping";
    document.getElementById("f-interval").value = d.poll_interval_seconds||"";
    renderMethodFields();
    if(d.method==="powershell"&&d.powershell){
      const remEl = document.getElementById("ps-remote");
      if(remEl) remEl.value = String(d.powershell.remote||false);
      if(document.getElementById("ps-username")) document.getElementById("ps-username").value = d.powershell.username||"";
      const enc = d.powershell.password?.startsWith("ENC:");
      if(document.getElementById("ps-password")) document.getElementById("ps-password").placeholder = enc?"(leave blank to keep encrypted)":"";
    }
    if(d.method==="ssh"&&d.ssh){
      if(document.getElementById("ssh-port"))     document.getElementById("ssh-port").value     = d.ssh.port||22;
      if(document.getElementById("ssh-username")) document.getElementById("ssh-username").value = d.ssh.username||"monitor";
      if(document.getElementById("ssh-keypath"))  document.getElementById("ssh-keypath").value  = d.ssh.key_path||"";
      const enc = d.ssh.password?.startsWith("ENC:");
      if(document.getElementById("ssh-password")) document.getElementById("ssh-password").placeholder = enc?"(leave blank to keep encrypted)":"";
    }
    if(d.method==="disk_usage"&&d.disk){
      if(document.getElementById("disk-os"))       document.getElementById("disk-os").value       = d.disk.os||"windows";
      if(document.getElementById("disk-path"))     document.getElementById("disk-path").value     = d.disk.path||"";
      if(document.getElementById("disk-username")) document.getElementById("disk-username").value = d.disk.username||"";
    }
    // V8.2: services/tasks watching
    if((d.method==="ssh"||d.method==="powershell")){
      const sw = d.services_watch||{}, tw = d.tasks_watch||{};
      if(document.getElementById("svc-watch-enabled"))  document.getElementById("svc-watch-enabled").checked = !!sw.enabled;
      if(document.getElementById("svc-watch-items"))    document.getElementById("svc-watch-items").value = (sw.items||[]).join("\n");
      if(document.getElementById("task-watch-enabled")) document.getElementById("task-watch-enabled").checked = !!tw.enabled;
      if(document.getElementById("task-watch-items"))   document.getElementById("task-watch-items").value = (tw.items||[]).join("\n");
    }
    const card = document.getElementById("add-device-card");
    card.querySelector(".card-title").textContent = "Edit Device";
    document.getElementById("btn-add-device").textContent = "Save changes";
    document.getElementById("btn-cancel-edit").style.display = "";
    card.style.display = "";
    card.scrollIntoView({behavior:"smooth"});
  } catch(e){ console.error("Edit modal error:", e); }
}

// ── Notify modal (V3.5) ────────────────────────────────────────────────────
let _notifyDeviceId = "";
let _knownEmails    = [];  // from email groups API

async function openNotifyModal(deviceId, deviceName){
  _notifyDeviceId = deviceId;
  document.getElementById("nm-device-name").textContent = deviceName;
  document.getElementById("notify-modal").classList.remove("hidden");

  // FIX #6 & #7: Load all known emails for checkbox pickers
  try{
    const gr = await fetch("/api/admin/email-groups",{headers:{"X-Session-Token":getSession()}});
    if(gr.ok){ const g = await gr.json(); _knownEmails = g.all_emails||[]; }
  } catch(_){}

  const r   = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/notify`,
                          {headers:{"X-Session-Token":getSession()}});
  const cfg = r.ok ? await r.json() : {};

  // FIX #7: checkbox enabled state
  document.getElementById("nm-enabled").checked     = cfg.notifications_enabled!==0;
  document.getElementById("nm-notify-emails").value = arrToEmailList(cfg.notify_emails||[]);
  document.getElementById("nm-esc-levels").value    = String(cfg.escalation_levels||1);

  // V8.4: trigger mode (previously missing from this modal -- only the
  // Settings-based notify modal had it) and the new repeat-alert cooldown.
  const tmSel = document.getElementById("nm-trigger-mode");
  if (tmSel) tmSel.value = cfg.alert_trigger_mode || "sustained";
  const waitField = document.getElementById("nm-wait-sec");
  if (waitField) waitField.value = cfg.escalation_after_sec_l1 || 60;
  const nmModeSel = document.getElementById("nm-notify-mode");
  if (nmModeSel) nmModeSel.value = cfg.alert_notify_mode || "immediate";
  const cdSec = document.getElementById("nm-cooldown-sec");
  if (cdSec) cdSec.value = cfg.notify_cooldown_sec || 300;
  toggleNmWaitField();
  toggleNmCooldownField();

  // FIX #7: show existing notify_emails as checked in picker
  renderNotifyEmailPicker(cfg.notify_emails||[]);
  window._nmSavedThr = cfg.thresholds||{};
  renderThresholdRows(cfg.thresholds||{}, deviceId);
  nmRenderBars(deviceId);
  renderEscLevels(cfg);
}

// V8.4: mirrors the equivalent functions in settings.js for the
// Settings-based notify modal -- same show/hide + sync pattern.
function toggleNmWaitField(){
  const mode  = document.getElementById("nm-trigger-mode")?.value;
  const field = document.getElementById("nm-wait-field");
  if (field) field.style.display = mode === "sustained" ? "flex" : "none";
}
function syncNmWaitToL1(){
  const waitVal = document.getElementById("nm-wait-sec")?.value;
  const l1 = document.getElementById("nm-esc-sec-l1");
  if (l1 && waitVal) l1.value = waitVal;
}
function toggleNmCooldownField(){
  const mode  = document.getElementById("nm-notify-mode")?.value;
  const field = document.getElementById("nm-cooldown-field");
  if (field) field.style.display = mode === "cooldown" ? "flex" : "none";
}

// FIX #7: notify email picker with checkboxes for known emails
function renderNotifyEmailPicker(current){
  const container = document.getElementById("nm-notify-email-picker");
  if(!container) return;
  if(!_knownEmails.length){ container.innerHTML=""; return; }
  container.innerHTML = `
    <p style="font-size:11.5px;color:var(--text-muted);margin-bottom:5px;">Quick-select from known emails:</p>
    <div style="display:flex;flex-wrap:wrap;gap:5px;">
      ${_knownEmails.map(e=>`
        <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;
          background:var(--bg-hover);padding:3px 8px;border-radius:4px;border:1px solid var(--border);">
          <input type="checkbox" data-email="${esc(e)}" data-target="nm-notify-emails"
            ${(current||[]).includes(e)?"checked":""}
            onchange="_syncEmailCheckbox(this)">
          ${esc(e)}</label>`).join("")}
    </div>`;
}

// FIX #6: renderEscLevels now pre-checks existing receivers
function renderEscLevels(cfg){
  cfg = cfg || {};
  const levels    = parseInt(document.getElementById("nm-esc-levels").value||"1");
  const container = document.getElementById("nm-esc-levels-container");
  if(levels === 0){ container.innerHTML=`<p style="color:var(--text-muted);font-size:12.5px;">Escalation disabled for this device.</p>`; return; }

  const levelDefs = [
    {n:1, label:"Level 1", color:"var(--status-warning)",
     secDef: cfg.escalation_after_sec_l1||cfg.escalation_after_sec||60,
     emailsDef: cfg.escalation_emails_l1||cfg.escalation_emails||[],
     smsDef: cfg.sms_numbers_l1||[], callDef: cfg.call_numbers_l1||[]},
    {n:2, label:"Level 2", color:"#FF8C00",
     secDef: cfg.escalation_after_sec_l2||600,
     emailsDef: cfg.escalation_emails_l2||[],
     smsDef: cfg.sms_numbers_l2||[], callDef: cfg.call_numbers_l2||[]},
    {n:3, label:"Level 3 (highest)", color:"var(--status-critical)",
     secDef: cfg.escalation_after_sec_l3||1200,
     emailsDef: cfg.escalation_emails_l3||[],
     smsDef: cfg.sms_numbers_l3||[], callDef: cfg.call_numbers_l3||[]},
  ];

  container.innerHTML = levelDefs.slice(0, levels).map(lv=>`
    <div style="border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;margin-bottom:10px;border-left:3px solid ${lv.color};">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
        <span style="font-size:12px;font-weight:700;color:${lv.color};background:${lv.color}22;padding:2px 8px;border-radius:4px;">⚡ ${lv.label}</span>
        <div class="field" style="margin:0;flex-direction:row;align-items:center;gap:6px;flex:1;">
          <label style="font-size:12px;white-space:nowrap;">Escalate after</label>
          <input id="nm-esc-sec-l${lv.n}" type="number" style="width:80px;" value="${lv.secDef}" min="60">
          <span style="font-size:12px;color:var(--text-muted);">seconds</span>
        </div>
      </div>
      <div class="field">
        <label style="font-size:12px;">Level ${lv.n} escalation emails <span style="color:var(--text-muted)">(Cc when this level fires)</span></label>
        <textarea id="nm-esc-emails-l${lv.n}" rows="2" class="code-textarea"
          placeholder="manager@corp.com">${arrToEmailList(lv.emailsDef)}</textarea>
        ${_renderEscEmailPicker("nm-esc-emails-l"+lv.n, lv.emailsDef)}
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;">
        <div class="field" style="margin:0;">
          <label style="font-size:12px;">📱 SMS numbers <span style="color:var(--text-muted)">(V8.5, one per line)</span></label>
          <textarea id="nm-sms-l${lv.n}" rows="2" class="code-textarea"
            placeholder="+15551234567">${(lv.smsDef||[]).join("\n")}</textarea>
        </div>
        <div class="field" style="margin:0;">
          <label style="font-size:12px;">☎ Call numbers <span style="color:var(--text-muted)">(V8.5, one per line)</span></label>
          <textarea id="nm-call-l${lv.n}" rows="2" class="code-textarea"
            placeholder="+15551234567">${(lv.callDef||[]).join("\n")}</textarea>
        </div>
      </div>
    </div>`).join("");
}

// FIX #6: email picker with pre-checked receivers + add/remove
function _renderEscEmailPicker(textareaId, current){
  if(!_knownEmails.length) return "";
  return `<div style="margin-top:5px;">
    <p style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">&#43; / &#8722; from known emails:</p>
    <div style="display:flex;flex-wrap:wrap;gap:5px;">
      ${_knownEmails.map(e=>`
        <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;
          background:var(--bg-hover);padding:3px 8px;border-radius:4px;border:1px solid var(--border);
          ${(current||[]).includes(e)?"border-color:var(--accent);background:rgba(79,209,197,.08)":""}">
          <input type="checkbox" data-email="${esc(e)}" data-target="${textareaId}"
            ${(current||[]).includes(e)?"checked":""}
            onchange="_syncEmailCheckbox(this)">
          ${esc(e)}</label>`).join("")}
    </div>
  </div>`;
}

function _syncEmailCheckbox(cb){
  const ta = document.getElementById(cb.dataset.target);
  if(!ta) return;
  const emails = emailListToArr(ta.value);
  const email  = cb.dataset.email;
  if(cb.checked){ if(!emails.includes(email)) emails.push(email); }
  else { const i = emails.indexOf(email); if(i>=0) emails.splice(i,1); }
  ta.value = arrToEmailList(emails);
  // Update sibling checkboxes for same email in same textarea
  document.querySelectorAll(`input[type=checkbox][data-target="${cb.dataset.target}"][data-email="${email}"]`).forEach(other=>{
    if(other !== cb) other.checked = cb.checked;
  });
}

// V11.1: the table now shows only the metrics that apply to this device's monitoring method
const NM_THR_IDS = {en:"thr-en-", w:"thr-w-", c:"thr-c-"};
let _nmMetrics = null;
async function renderThresholdRows(saved, deviceId){
  const container = document.getElementById("nm-thresholds");
  _nmMetrics = null;
  container.innerHTML = '<div style="color:var(--text-muted);padding:8px">Loading metrics\u2026</div>';
  let meta;
  try { meta = await ThrUI.load(); }
  catch(e){ container.innerHTML = '<div style="color:var(--status-critical);padding:8px">Could not load the metric list ('+ThrUI.esc(e.message)+'). Close and reopen this window.</div>'; return; }
  const method = (window._devMethods||{})[deviceId] || "ping";
  _nmMetrics = ThrUI.metricsFor(meta, method);
  container.innerHTML = ThrUI.tableHTML(meta, _nmMetrics, saved, NM_THR_IDS, {wait:false}) +
    '<div style="margin-top:8px"><button type="button" class="btn secondary small" onclick="nmFillRecommended()">Fill recommended values</button></div>';
}
function nmFillRecommended(){
  const meta = ThrUI.get(); if(!meta || !_nmMetrics) return;
  ThrUI.fillRecommended(meta, _nmMetrics, NM_THR_IDS);
}

// returns {thresholds, errors}; if the table never rendered, keep what is saved
function collectThresholds(){
  if(!_nmMetrics || !ThrUI.get()) return {thresholds: (window._nmSavedThr||{}), errors: []};
  return ThrUI.collect(ThrUI.get(), _nmMetrics, NM_THR_IDS, {wait:false});
}

function _getEscEmails(level){
  const ta = document.getElementById("nm-esc-emails-l"+level);
  return ta ? emailListToArr(ta.value) : [];
}
function _getEscSec(level){
  const el = document.getElementById("nm-esc-sec-l"+level);
  return el ? (parseInt(el.value)||60) : 60;
}
// V8.5
function _getSmsNumbers(level){
  const ta = document.getElementById("nm-sms-l"+level);
  return ta ? phoneListToArr(ta.value) : [];
}
function _getCallNumbers(level){
  const ta = document.getElementById("nm-call-l"+level);
  return ta ? phoneListToArr(ta.value) : [];
}

async function saveNotifyModal(){
  const levels = parseInt(document.getElementById("nm-esc-levels").value||"1");
  const thr = collectThresholds();
  if(thr.errors.length){
    const st0 = document.getElementById("nm-status");
    st0.textContent = thr.errors[0]; st0.style.color = "var(--status-critical)";
    return;
  }
  const payload = {
    notifications_enabled:   document.getElementById("nm-enabled").checked ? 1 : 0,
    notify_emails:           emailListToArr(document.getElementById("nm-notify-emails").value),
    escalation_levels:       levels,
    escalation_emails_l1:    levels>=1 ? _getEscEmails(1) : [],
    escalation_emails_l2:    levels>=2 ? _getEscEmails(2) : [],
    escalation_emails_l3:    levels>=3 ? _getEscEmails(3) : [],
    escalation_after_sec_l1: levels>=1 ? _getEscSec(1) : 60,
    escalation_after_sec_l2: levels>=2 ? _getEscSec(2) : 600,
    escalation_after_sec_l3: levels>=3 ? _getEscSec(3) : 1200,
    thresholds: thr.thresholds,
    alert_trigger_mode:  document.getElementById("nm-trigger-mode")?.value || "sustained",
    alert_notify_mode:   document.getElementById("nm-notify-mode")?.value || "immediate",
    notify_cooldown_sec: parseInt(document.getElementById("nm-cooldown-sec")?.value) || 300,
    sms_numbers_l1:  levels>=1 ? _getSmsNumbers(1) : [],
    sms_numbers_l2:  levels>=2 ? _getSmsNumbers(2) : [],
    sms_numbers_l3:  levels>=3 ? _getSmsNumbers(3) : [],
    call_numbers_l1: levels>=1 ? _getCallNumbers(1) : [],
    call_numbers_l2: levels>=2 ? _getCallNumbers(2) : [],
    call_numbers_l3: levels>=3 ? _getCallNumbers(3) : [],
  };
  const r = await fetch(`/api/devices/${encodeURIComponent(_notifyDeviceId)}/notify`,
    {method:"POST", headers:authHeaders(), body:JSON.stringify(payload)});
  const st = document.getElementById("nm-status");
  if(r.ok){
    st.textContent="Saved ✓"; st.style.color="var(--status-ok)";
    setTimeout(()=>st.textContent="",2500);
  } else {
    let em = "Save failed";
    try { const j = await r.json(); if(j && j.error) em = j.error; } catch(_){}
    st.textContent = em; st.style.color = "var(--status-critical)";
  }
}

function closeNotifyModal(){ document.getElementById("notify-modal").classList.add("hidden"); }

// ── callbacks from auth.js ─────────────────────────────────────────────────
function onAdminLogin(){
  loadDevices();
  document.getElementById("add-device-form").style.opacity  = "";
  document.getElementById("add-device-form").style.pointerEvents = "";
  document.getElementById("admin-required-msg").style.display = "none";
}
function onAdminLogout(){ loadDevices(); }

document.addEventListener("DOMContentLoaded", ()=>{
  document.getElementById("f-method").addEventListener("change", renderMethodFields);
  document.getElementById("btn-add-device").addEventListener("click", addDevice);
  renderMethodFields();
  loadDevices();
  const role = getRole();
  if(role !== "admin"){
    document.getElementById("admin-required-msg").style.display = "";
    document.getElementById("add-device-form").style.opacity = "0.4";
    document.getElementById("add-device-form").style.pointerEvents = "none";
  }
});

// V11.3 patch 06: the "apply to ..." bars of the Notify window are built from the device being edited:
// this device / same type / same check method / all devices (or all sites) / the current search-or-filter.
let _nmTargets = [];
function nmFilterIds(){
  return [...document.querySelectorAll("#device-list [data-mon-id]")].filter(r => r.style.display !== "none").map(r => r.getAttribute("data-mon-id"));
}
async function nmRenderBars(deviceId){
  const tb = document.getElementById("nm-apply-timing"), hb = document.getElementById("nm-apply-thr");
  if(tb) tb.innerHTML = ""; if(hb) hb.innerHTML = "";
  let ctx; try{ ThrUI.resetContext(); ctx = await ThrUI.context(deviceId); }catch(e){ return; }
  if(deviceId !== _notifyDeviceId) return;
  const fi = nmFilterIds(), narrowed = fi.length > 0 && fi.length < (_devList||[]).length;
  _nmTargets = ThrUI.targets(ctx.dev, ctx.facets, narrowed ? fi : null, {every:true, methods:ctx.methodOf});
  if(tb) tb.innerHTML = ThrUI.barHTML("Apply wait & cooldown to:", _nmTargets, "nmApplyTiming");
  if(hb) hb.innerHTML = ThrUI.barHTML("Apply the thresholds above to:", _nmTargets.filter(t => t.key !== "all"), "nmApplyThr");
}
async function nmApplyTiming(key){
  const t = _nmTargets.find(x => x.key === key); if(!t) return;
  try{ const res = await ThrUI.applyTiming(t, "nm"); if(res.cancelled) return; showToast(res.message, res.ok ? "success" : "error"); if(res.ok) ThrUI.resetContext(); }
  catch(e){ showToast("Apply failed: " + e.message, "error"); }
}
async function nmApplyThr(key){
  const t = _nmTargets.find(x => x.key === key); if(!t) return;
  const col = collectThresholds();
  if(col.errors.length){ showToast(col.errors[0], "error"); return; }
  try{ const res = await ThrUI.applyThr(t, col.thresholds); if(res.cancelled) return; showToast(res.message, res.ok ? "success" : "error"); }
  catch(e){ showToast("Apply failed: " + e.message, "error"); }
}

// V11.2: "Apply wait & cooldown to ..." buttons (Escalation tab, notify windows). prefix = id prefix of the 4 timing fields.
async function applyTimingBtn(scope, prefix){
  try{
    const res=await ThrUI.applyTiming(scope,prefix);
    if(res.cancelled) return;
    showToast(res.message, res.ok?"success":"error");
    
  }catch(e){ showToast("Apply failed: "+e.message,"error"); }
}

// V11.3 patch 04: deep links from the dashboard device window -- /devices#edit=<id> and /devices#notify=<id>
let _hashHandled = false;
function _openFromHash(devices){
  if(_hashHandled) return;
  const m = (location.hash || "").match(/^#(edit|notify)=(.+)$/);
  if(!m) return;
  _hashHandled = true;
  const id = decodeURIComponent(m[2]), dev = (devices || []).find(x => x.id === id);
  history.replaceState(null, "", location.pathname + location.search);
  if(!dev){ showToast("That device no longer exists", "error"); return; }
  if(m[1] === "edit") openEditModal(JSON.stringify(dev)); else openNotifyModal(dev.id, dev.name);
}
