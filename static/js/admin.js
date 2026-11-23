/* =============================================================================
 * Net-monit V12.4
 * Copyright (c) 2024-2026 Abdullah. All rights reserved.
 * Contact: abuabdullah.be@outlook.com
 * ============================================================================= */
/* admin.js — V3.5
 * FIXES:
 * #4  Admin page fully renders users, SMTP groups, notification groups, audit log
 * #3  checkAccess fixed — page content shows for admin session
 * ============================================================================= */
"use strict";

const esc2 = s => String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
const v2   = id => document.getElementById(id);
const fmtEmails2 = a => (a||[]).join("\n");
const parseEmails2 = t => t.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
const timeAgo2 = ts => {
  if(!ts) return "never";
  const d=Math.max(0,Date.now()/1000-ts);
  if(d<60)    return `${Math.floor(d)}s ago`;
  if(d<3600)  return `${Math.floor(d/60)}m ago`;
  if(d<86400) return `${Math.floor(d/3600)}h ago`;
  return `${Math.floor(d/86400)}d ago`;
};
const setStatus2 = (id,msg,ok) => {
  const el=v2(id); if(!el) return;
  el.textContent=msg;
  el.style.color=ok?"var(--status-ok)":"var(--status-critical)";
  setTimeout(()=>{ el.textContent=""; },4000);
};

// ── FIX #3/#4: Access gate ─────────────────────────────────────────────────
function checkAccess(){
  const role = sessionStorage.getItem("netmon_role");
  const sess = getSession();
  const isAdm = role==="admin" && !!sess;
  v2("admin-locked")  && (v2("admin-locked").style.display  = isAdm ? "none" : "");
  v2("admin-content") && (v2("admin-content").style.display = isAdm ? "" : "none");
  if(isAdm) initAdmin();
}
function onAdminLogin()  { checkAccess(); }
function onAdminLogout() { checkAccess(); }

// ── Tab switching ─────────────────────────────────────────────────────────
function adminTab(name){
  document.querySelectorAll(".atab").forEach(b=>b.classList.toggle("active",b.dataset.tab===name));
  document.querySelectorAll(".atab-panel").forEach(p=>p.classList.toggle("active",p.id==="at-"+name));
  ADMIN_LOADERS[name] && ADMIN_LOADERS[name]();
}
const ADMIN_LOADERS = {
  users:     loadAdminUsers,
  email:     loadAdminEmail,
  groups:    loadAdminGroups,
  audit:     loadAdminAudit,
  system:    loadAdminSystem,
  backup:    () => { v2("backup-export-status").textContent=""; v2("backup-restore-status").textContent=""; },
};

/* ═══════════════════════════════════════════════════════════
   TAB 1 — USER MANAGEMENT
═══════════════════════════════════════════════════════════ */
const ROLE_META = {
  admin:      { label: "⚙ admin",      bg: "rgba(59,139,235,.15)",  fg: "var(--accent)",         bd: "rgba(59,139,235,.3)"  },
  supervisor: { label: "🛡 supervisor", bg: "rgba(158,119,237,.15)", fg: "#9E77ED",               bd: "rgba(158,119,237,.3)" },
  user:       { label: "👁 view",       bg: "rgba(242,184,75,.12)",  fg: "var(--status-warning)", bd: "rgba(242,184,75,.25)" },
};

async function loadAdminUsers(){
  try{
    const r = await fetch("/api/admin/users",{headers:{"X-Session-Token":getSession()}});
    if(!r.ok) return;
    const users = await r.json();
    v2("admin-user-count") && (v2("admin-user-count").textContent = `${users.length} user(s)`);
    const tbody = v2("admin-users-tbody"); if(!tbody) return;
    tbody.innerHTML = users.length ? users.map(u=>{
      const meta = ROLE_META[u.role] || ROLE_META.user;
      return `<tr>
        <td>
          <div style="display:flex;align-items:center;gap:6px;">
            <strong id="au-email-${u.id}">${esc2(u.email)}</strong>
            <button class="btn secondary small" title="Edit email" onclick="adminEditEmail(${u.id},'${esc2(u.email)}')" style="padding:1px 7px;">✎</button>
          </div>
        </td>
        <td>
          <select class="admin-role-select" onchange="adminChangeRole('${esc2(u.email)}', this.value)"
            style="background:${meta.bg};color:${meta.fg};border:1px solid ${meta.bd};border-radius:4px;font-size:11.5px;font-weight:700;padding:3px 6px;">
            <option value="admin"      ${u.role==='admin'?'selected':''}>⚙ admin</option>
            <option value="supervisor" ${u.role==='supervisor'?'selected':''}>🛡 supervisor</option>
            <option value="user"       ${u.role==='user'?'selected':''}>👁 view</option>
          </select>
        </td>
        <td><span style="color:${u.active?"var(--status-ok)":"var(--text-muted)"}">${u.active?"● Active":"○ Inactive"}</span></td>
        <td style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 4px;">
          <button class="btn secondary small" onclick="adminResetToken('${esc2(u.email)}')">🔑 Token</button>
          <button class="btn danger small"    onclick="adminDeleteUser('${esc2(u.email)}')">Remove</button>
        </td>
      </tr>`;
    }).join("") : `<tr><td colspan="4" style="color:var(--text-muted);text-align:center;padding:20px;">No users yet.</td></tr>`;
  }catch(e){ console.error("loadAdminUsers",e); }
}

async function adminEditEmail(userId, currentEmail){
  const newEmail = prompt(`Fix the email for this account:`, currentEmail);
  if(newEmail===null || newEmail.trim().toLowerCase()===currentEmail.toLowerCase()) return;
  const r = await fetch(`/api/admin/users/${userId}/email`,{method:"PUT",headers:authHeaders(),body:JSON.stringify({email:newEmail.trim()})});
  const d = await r.json();
  if(r.ok){ showToast(`Email updated to ${d.email}`,"success"); loadAdminUsers(); }
  else showToast(d.error||"Failed","error");
}

async function adminGenToken(){
  try{
    const r=await fetch("/api/admin/generate-token",{headers:{"X-Session-Token":getSession()}});
    const d=await r.json();
    if(d.token){ v2("au-token").value=d.token; adminCheckToken(); }
  }catch(e){}
}
function adminCheckToken(){
  const t=v2("au-token")?.value||"";
  const bar=v2("au-strength-bar"); const hint=v2("au-strength-hint");
  if(!bar||!hint) return;
  const ok={len:t.length>=8,up:/[A-Z]/.test(t),lo:/[a-z]/.test(t),di:/[0-9]/.test(t)};
  const score=Object.values(ok).filter(Boolean).length;
  bar.style.width=score<=2?"33%":score===3?"66%":"100%";
  bar.style.background=score<=2?"#FF5C5C":score===3?"#F2B84B":"#3DD68C";
  hint.innerHTML=`<span style="color:${ok.len?"#3DD68C":"#FF5C5C"}">8+ chars</span>&nbsp;
    <span style="color:${ok.up?"#3DD68C":"#FF5C5C"}">A-Z</span>&nbsp;
    <span style="color:${ok.lo?"#3DD68C":"#FF5C5C"}">a-z</span>&nbsp;
    <span style="color:${ok.di?"#3DD68C":"#FF5C5C"}">0-9</span>`;
}
async function adminAddUser(){
  const email=v2("au-email")?.value.trim().toLowerCase()||"";
  const role =v2("au-role")?.value||"user";
  const token=v2("au-token")?.value.trim()||"";
  if(!email||!token){ setStatus2("au-status","Email and token required",false); return; }
  if(token.length<8||!/[A-Z]/.test(token)||!/[a-z]/.test(token)||!/[0-9]/.test(token)){
    setStatus2("au-status","Token needs 8+ chars, uppercase, lowercase, number",false); return;
  }
  const r=await fetch("/api/admin/users",{method:"POST",headers:authHeaders(),body:JSON.stringify({email,role,token})});
  const d=await r.json();
  if(r.ok){
    const em=d.welcome_email_sent?"· welcome email sent ✓":`(SMTP not configured)`;
    setStatus2("au-status",`${email} added ${em}`,true);
    if(v2("au-email")) v2("au-email").value="";
    if(v2("au-token")) v2("au-token").value="";
    loadAdminUsers();
  } else { setStatus2("au-status",d.error||"Failed",false); }
}
async function adminChangeRole(email, newRole){
  if(!confirm(`Change "${email}" to role: ${newRole}?`)) return;
  const t = await _adminGenTokenFetch();
  const r=await fetch("/api/admin/users",{method:"POST",headers:authHeaders(),body:JSON.stringify({email,role:newRole,token:t})});
  if(r.ok){ showToast(`${email} → ${newRole}`,"success"); loadAdminUsers(); }
  else showToast("Failed","error");
}
async function adminResetToken(email){
  const t=prompt(`New token for "${email}":\n(8+ chars, upper + lower + number)`);
  if(t===null) return;
  if(t.length<8||!/[A-Z]/.test(t)||!/[a-z]/.test(t)||!/[0-9]/.test(t)){
    showToast("Token too weak","error"); return;
  }
  const r=await fetch(`/api/admin/users/${encodeURIComponent(email)}/token`,{method:"PUT",headers:authHeaders(),body:JSON.stringify({token:t})});
  const d=await r.json();
  showToast(r.ok?`Token reset${d.welcome_email_sent?" · email sent ✓":""}`: "Failed", r.ok?"success":"error");
}
async function adminDeleteUser(email){
  if(!confirm(`Remove "${email}"? They will lose access immediately.`)) return;
  const r=await fetch(`/api/admin/users/${encodeURIComponent(email)}`,{method:"DELETE",headers:authHeaders()});
  if(r.ok){ showToast(`${email} removed`,"success"); loadAdminUsers(); }
  else showToast("Failed","error");
}
async function _adminGenTokenFetch(){
  try{ const r=await fetch("/api/admin/generate-token",{headers:{"X-Session-Token":getSession()}}); const d=await r.json(); return d.token||""; }
  catch(_){ return ""; }
}

/* ═══════════════════════════════════════════════════════════
   TAB 2 — EMAIL SETTINGS (SMTP)
═══════════════════════════════════════════════════════════ */
async function loadAdminEmail(){
  try{
    const r=await fetch("/api/settings/smtp",{headers:{"X-Session-Token":getSession()}});
    if(!r.ok) return;
    const s=await r.json();
    v2("ae-enabled") && (v2("ae-enabled").value = String(!!s.enabled));
    v2("ae-host")    && (v2("ae-host").value    = s.host||"");
    v2("ae-port")    && (v2("ae-port").value    = s.port||587);
    v2("ae-tls")     && (v2("ae-tls").value     = s.use_tls!==false?"true":"false");
    v2("ae-username")&& (v2("ae-username").value= s.username||"");
    v2("ae-from")    && (v2("ae-from").value    = s.from_address||"");
    v2("ae-resend")  && (v2("ae-resend").value  = s.resend_interval_minutes||30);
    v2("ae-admin-emails")  && (v2("ae-admin-emails").value   = fmtEmails2(s.admin_emails||s.to_addresses||[]));
    v2("ae-support-emails")&& (v2("ae-support-emails").value = fmtEmails2(s.support_emails||[]));
    v2("ae-manager-emails")&& (v2("ae-manager-emails").value = fmtEmails2(s.manager_emails||[]));
  }catch(e){ console.error("loadAdminEmail",e); }
}
async function saveAdminEmail(){
  const pw=v2("ae-password")?.value||"";
  const payload={
    enabled:                 v2("ae-enabled")?.value==="true",
    host:                    v2("ae-host")?.value.trim()||"",
    port:                    parseInt(v2("ae-port")?.value||"587"),
    use_tls:                 v2("ae-tls")?.value!=="false",
    username:                v2("ae-username")?.value.trim()||"",
    from_address:            v2("ae-from")?.value.trim()||"",
    resend_interval_minutes: parseInt(v2("ae-resend")?.value||"30"),
    admin_emails:            parseEmails2(v2("ae-admin-emails")?.value||""),
    support_emails:          parseEmails2(v2("ae-support-emails")?.value||""),
    manager_emails:          parseEmails2(v2("ae-manager-emails")?.value||""),
  };
  payload.to_addresses=payload.admin_emails;
  if(pw) payload.password=pw;
  const r=await fetch("/api/settings/smtp",{method:"POST",headers:authHeaders(),body:JSON.stringify(payload)});
  setStatus2("ae-status", r.ok?"Saved ✓":"Save failed", r.ok);
  if(r.ok && v2("ae-password")) v2("ae-password").value="";
  if(r.ok) loadAdminGroups();
}
async function adminTestEmail(state){
  const r=await fetch("/api/settings/test-email",{method:"POST",headers:authHeaders(),body:JSON.stringify({state})});
  const d=await r.json();
  showToast(d.ok?`Test ${state} email sent ✓`:`Email failed: ${d.message}`, d.ok?"success":"error");
}

/* ═══════════════════════════════════════════════════════════
   TAB 3 — EMAIL GROUPS
═══════════════════════════════════════════════════════════ */
async function loadAdminGroups(){
  try{
    const r=await fetch("/api/admin/email-groups",{headers:{"X-Session-Token":getSession()}});
    if(!r.ok) return;
    const g=await r.json();
    v2("ag-admin-emails")  && (v2("ag-admin-emails").value   = fmtEmails2(g.admin_emails||[]));
    v2("ag-support-emails")&& (v2("ag-support-emails").value = fmtEmails2(g.support_emails||[]));
    v2("ag-manager-emails")&& (v2("ag-manager-emails").value = fmtEmails2(g.manager_emails||[]));
    renderGroupSummary(g);
  }catch(e){ console.error("loadAdminGroups",e); }
}
function renderGroupSummary(g){
  const c=v2("ag-summary"); if(!c) return;
  const all=g.all_emails||[];
  c.innerHTML=`
    <div class="info-grid">
      <div class="info-tile"><div class="info-val">${all.length}</div><div class="info-lbl">Total known emails</div></div>
      <div class="info-tile"><div class="info-val">${(g.admin_emails||[]).length}</div><div class="info-lbl">Admin group</div></div>
      <div class="info-tile"><div class="info-val">${(g.support_emails||[]).length}</div><div class="info-lbl">Support group</div></div>
      <div class="info-tile"><div class="info-val">${(g.manager_emails||[]).length}</div><div class="info-lbl">Manager group</div></div>
    </div>
    ${all.length?`<div style="margin-top:10px;"><p style="font-size:12px;color:var(--text-muted);margin-bottom:5px;">All known emails (available in notification pickers):</p>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">
        ${all.map(e=>`<span style="background:var(--bg-hover);padding:2px 9px;border-radius:4px;font-size:12px;font-family:var(--font-mono)">${esc2(e)}</span>`).join("")}
      </div></div>`:""}`;
}
async function saveAdminGroups(){
  const payload={
    admin_emails:   parseEmails2(v2("ag-admin-emails")?.value||""),
    support_emails: parseEmails2(v2("ag-support-emails")?.value||""),
    manager_emails: parseEmails2(v2("ag-manager-emails")?.value||""),
  };
  // Save groups via SMTP endpoint (groups live in smtp config)
  const r=await fetch("/api/settings/smtp",{method:"POST",headers:authHeaders(),body:JSON.stringify(payload)});
  setStatus2("ag-status", r.ok?"Saved ✓":"Save failed", r.ok);
  if(r.ok) loadAdminGroups();
}

/* ═══════════════════════════════════════════════════════════
   TAB 4 — AUDIT LOG
═══════════════════════════════════════════════════════════ */
async function loadAdminAudit(){
  try{
    const r=await fetch("/api/audit?limit=200",{headers:{"X-Session-Token":getSession()}});
    if(!r.ok) return;
    const logs=await r.json();
    const tbody=v2("audit-tbody"); if(!tbody) return;
    tbody.innerHTML=logs.length ? logs.map(l=>`<tr>
      <td style="font-size:11.5px;white-space:nowrap;color:var(--text-muted)">${new Date(l.ts*1000).toLocaleString()}</td>
      <td style="font-family:var(--font-mono);font-size:12px;color:var(--accent)">${esc2(l.actor||"system")}</td>
      <td><span class="audit-badge">${esc2(l.action||"")}</span></td>
      <td style="font-size:12px">${esc2(l.target||"")}</td>
      <td style="font-size:11.5px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc2(l.detail||"")}</td>
    </tr>`).join("") : `<tr><td colspan="5" style="color:var(--text-muted);text-align:center;padding:20px">No audit entries yet</td></tr>`;
  }catch(e){ console.error("loadAdminAudit",e); }
}

/* ═══════════════════════════════════════════════════════════
   TAB 5 — SYSTEM INFO
═══════════════════════════════════════════════════════════ */
async function loadAdminSystem(){
  try{
    const [statR, devR] = await Promise.all([
      fetch("/api/status",  {headers:{"X-Session-Token":getSession()}}),
      fetch("/api/devices", {headers:{"X-Session-Token":getSession()}}),
    ]);
    const stat = statR.ok  ? await statR.json()  : {};
    const devs = devR.ok   ? await devR.json()   : [];
    const c=v2("admin-sys-info"); if(!c) return;
    const summary = stat.summary||{};
    c.innerHTML=`
      <div class="info-grid">
        <div class="info-tile"><div class="info-val" style="color:var(--accent)">V${stat.version||"12.4"}</div><div class="info-lbl">App Version</div></div>
        <div class="info-tile"><div class="info-val">${devs.length}</div><div class="info-lbl">Total Devices</div></div>
        <div class="info-tile"><div class="info-val" style="color:var(--status-ok)">${summary.ok||0}</div><div class="info-lbl">Healthy</div></div>
        <div class="info-tile"><div class="info-val" style="color:var(--status-warning)">${summary.warning||0}</div><div class="info-lbl">Warning</div></div>
        <div class="info-tile"><div class="info-val" style="color:var(--status-critical)">${summary.critical||0}</div><div class="info-lbl">Critical</div></div>
        <div class="info-tile"><div class="info-val" style="color:var(--text-muted)">${summary.offline||0}</div><div class="info-lbl">Offline</div></div>
      </div>
      <div style="margin-top:14px;">
        <p style="font-size:12px;color:var(--text-muted);">Server time: ${new Date((stat.server_time||Date.now()/1000)*1000).toLocaleString()}</p>
        <p style="font-size:12px;color:var(--text-muted);">© 2024–2026 Net-monit V12.4 — Developed by Abdullah — InfoXtek.com</p>
      </div>`;
  }catch(e){ console.error("loadAdminSystem",e); }
}

/* ═══════════════════════════════════════════════════════════
   TAB 6 — BACKUP & RESTORE (V8.4)
═══════════════════════════════════════════════════════════ */
async function exportConfig(){
  setStatus2("backup-export-status", "Preparing download…", true);
  try{
    const includeUsers = v2("backup-include-users")?.checked !== false;
    const r = await fetch(`/api/admin/config/export?users=${includeUsers ? "1" : "0"}`,
                           {headers:{"X-Session-Token":getSession()}});
    if(!r.ok){ setStatus2("backup-export-status","Export failed",false); return; }
    // Content-Disposition on the response already names the file --
    // pull it out so the downloaded file matches the server's timestamp
    // rather than guessing a name client-side.
    const cd = r.headers.get("Content-Disposition") || "";
    const m  = cd.match(/filename="([^"]+)"/);
    const filename = m ? m[1] : `netmonit-config-backup-${Date.now()}.json`;
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setStatus2("backup-export-status", `Downloaded ${filename} ✓`, true);
  }catch(e){ setStatus2("backup-export-status","Export failed",false); }
}

async function restoreConfig(){
  const fileInput = v2("backup-restore-file");
  const file = fileInput?.files?.[0];
  if(!file){ setStatus2("backup-restore-status","Choose a backup file first",false); return; }

  const includeUsers = v2("backup-restore-users")?.checked !== false;
  if(!confirm(
    "This will REPLACE your current devices, SMTP settings, templates, custom placeholders, " +
    "thresholds, and escalation settings with the contents of this file" +
    (includeUsers ? ", and add/update user accounts from it" : "") +
    ".\n\nThis cannot be undone. Have you downloaded a fresh backup of your CURRENT configuration " +
    "first, in case you want to go back?\n\nClick OK to proceed with the restore."
  )) return;

  let parsed;
  try{
    const text = await file.text();
    parsed = JSON.parse(text);
  }catch(e){
    setStatus2("backup-restore-status","That file isn't valid JSON — is it really a Net-monit config export?",false);
    return;
  }

  setStatus2("backup-restore-status", "Restoring…", true);
  try{
    const r = await fetch("/api/admin/config/import", {
      method: "POST",
      headers: {"Content-Type":"application/json","X-Session-Token":getSession()},
      body: JSON.stringify({data: parsed, include_users: includeUsers})
    });
    const d = await r.json();
    if(!r.ok){ setStatus2("backup-restore-status", d.error || "Restore failed", false); return; }
    setStatus2("backup-restore-status",
      `Restored ✓ (${d.device_count} device${d.device_count===1?"":"s"}). Reloading…`, true);
    setTimeout(() => location.reload(), 1500);
  }catch(e){ setStatus2("backup-restore-status","Restore failed",false); }
}

/* ═══════════════════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════════════════ */
function initAdmin(){
  loadAdminUsers();
  setInterval(()=>{
    if(document.getElementById("at-audit")?.classList.contains("active")) loadAdminAudit();
  }, 20000);
}

document.addEventListener("DOMContentLoaded", ()=>{
  document.querySelectorAll(".atab").forEach(b=>b.addEventListener("click",()=>adminTab(b.dataset.tab)));
  v2("btn-admin-save-email")    ?.addEventListener("click", saveAdminEmail);
  v2("btn-admin-test-warn")     ?.addEventListener("click", ()=>adminTestEmail("warning"));
  v2("btn-admin-test-crit")     ?.addEventListener("click", ()=>adminTestEmail("critical"));
  v2("btn-admin-save-groups")   ?.addEventListener("click", saveAdminGroups);
  v2("au-token")                ?.addEventListener("input",  adminCheckToken);
  checkAccess();
});
