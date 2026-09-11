/* NFI Admin Panel - front-end logic */
(function () {
  "use strict";

  const state = {
    me: null,
    users: [],
    games: [],
    apps: [],
    projects: [],
    orders: [],
    invoices: [],
    channels: [],
    settings: {},
    activeView: "dashboard",
    mediaDetail: null,   // {type:'games'|'apps', id}
    chat: { sel: { kind: "main", id: null, title: "چت اصلی" } },
    teams: [],
    people: [],
    personDetail: null,
    manageTab: "doc",
    peopleFilter: { kind: "all", q: "" },
    tempPhoto: null,
    docRange: null,
    docData: null,
    notifications: [],
    notifUnread: 0,
    warnings: [],
    seenWarnings: {},
    seenAlerts: {},
    editingId: null,
    chatMaxAt: 0,
  };
  let chatPollGen = 0;

  const $ = (sel, root) => (root || document).querySelector(sel);
  const RANK = { admin: 5, manager: 4, supervisor: 3, developer: 2, employee: 1, viewer: 0 };
  const ROLE_FA = { admin: "ادمین", manager: "مدیر", supervisor: "سرپرست", developer: "دولپر", employee: "کارمند", viewer: "هم‌تیمی" };
  const ORDER_TYPE_FA = { site: "سایت", program: "برنامه", game: "بازی", repair: "تعمیر", other: "سایر" };
  const PROJECT_STATUS_FA = { active: "در حال انجام", pending: "در انتظار", done: "تکمیل شده", canceled: "لغو شده" };
  const INVOICE_TYPE_FA = { sale: "فروش", buy: "خرید" };
  const INVOICE_STATUS_FA = { pending: "در انتظار تایید", approved: "تایید شده", rejected: "رد شده" };
  const ALERT_COLORS = ["#2ed9a4", "#ff5c7a", "#ffc24b", "#6d5df6", "#3ec6ff"];

  // ---------------- helpers ----------------
  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  }

  function fmtMoney(n, cur) {
    const c = (cur ?? "$");
    if (n === "" || n === null || n === undefined || isNaN(parseFloat(n))) return "—";
    return parseFloat(n).toLocaleString("en-US") + " " + c;
  }

  function fmtTime(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    return d.toLocaleString("fa-IR", { dateStyle: "short", timeStyle: "short" });
  }

  function toast(msg, type) {
    const wrap = $("#toast-wrap");
    if (!wrap) return;
    const el = document.createElement("div");
    el.className = "toast " + (type || "info");
    el.textContent = msg;
    wrap.appendChild(el);
    setTimeout(() => {
      el.style.transition = "opacity 0.4s";
      el.style.opacity = "0";
      setTimeout(() => el.remove(), 400);
    }, 3200);
  }

  async function api(path, opts) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      ...opts,
    });
    let data = {};
    try { data = await res.json(); } catch (e) {}
    if (!res.ok) {
      const err = new Error(data.error || "Request failed");
      err.status = res.status;
      if (res.status === 401) { showAuth("login"); }
      throw err;
    }
    return data;
  }

  // role helpers
  function canEdit() { return ["admin", "manager", "developer"].includes(state.me.role); }
  function canInvoice() { return ["admin", "manager", "developer", "employee"].includes(state.me.role); }
  function isApprover() { return ["admin", "manager"].includes(state.me.role); }
  function isAdmin() { return state.me.role === "admin"; }
  function canWarn() { return isAdmin() || !!state.me.can_warn; }
  function canModChat() { return isAdmin() || !!state.me.mod_chat; }
  function canAlert() { return canEdit(); }

  function canEditMedia() { return ["admin", "manager", "supervisor", "developer"].includes(state.me.role); }
  function canManagePeople() { return ["admin", "manager", "supervisor"].includes(state.me.role); }
  function canManageTeams() { return canManagePeople(); }
  function canViewDoc() { return canManagePeople(); }

  function roleBadge(r) {
    return r === "admin" ? "admin" : r === "manager" ? "amber" : r === "supervisor" ? "super" : r === "developer" ? "green" : r === "employee" ? "red" : "user";
  }
  const PERSON_KIND_FA = { manager: "مدیر", supervisor: "سرپرست", teammate: "هم‌تیمی", customer: "مشتری", partner: "همکار" };
  const PRESENCE_FA = { present: "حاضر", absent: "غایب", vacation: "مرخصی", leave: "در رفت", other: "سایر" };
  const PERSON_KIND_BADGE = { manager: "amber", supervisor: "super", teammate: "user", customer: "green", partner: "admin" };

  function creatableRoles(role) {
    if (role === "admin") return ["admin", "manager", "supervisor", "developer", "employee", "viewer"];
    if (role === "manager") return ["manager", "supervisor", "developer", "employee", "viewer"];
    if (role === "developer") return ["developer", "employee", "viewer"];
    return [];
  }
  function canManageUser(target) {
    if (!state.me || !target) return false;
    if (target.username === state.me.username) return false;
    if (target.role === "admin") return isAdmin();
    return RANK[target.role] <= RANK[state.me.role];
  }

  // ---------------- Auth screens ----------------
  function showAuth(mode) {
    $("#layout").style.display = "none";
    $("#auth-screen").style.display = "flex";
    const title = $("#auth-title"), sub = $("#auth-sub"), form = $("#auth-form");
    $("#auth-msg").style.display = "none";
    if (mode === "setup") {
      title.textContent = "ساخت اکانت ادمین";
      sub.textContent = "برای اولین بار، ادمین اصلی سامانه را بسازید";
      form.innerHTML = `
        <div class="field"><label>نام و نام خانوادگی *</label><input type="text" id="a-name" required placeholder="مثلاً: علی رضایی"></div>
        <div class="field"><label>نام کاربری *</label><input type="text" id="a-username" required placeholder="admin"></div>
        <div class="field"><label>رمز عبور * (حداقل ۶ کاراکتر)</label><input type="password" id="a-password" required minlength="6"></div>
        <button type="submit" class="btn btn-primary btn-block">ساخت اکانت ادمین</button>`;
    } else {
      title.textContent = "ورود به پنل";
      sub.textContent = "به حساب کاربری خود وارد شوید";
      form.innerHTML = `
        <div class="field"><label>نام کاربری</label><input type="text" id="a-username" required autocomplete="username"></div>
        <div class="field"><label>رمز عبور</label><input type="password" id="a-password" required autocomplete="current-password"></div>
        <button type="submit" class="btn btn-primary btn-block">ورود</button>`;
    }
    form.onsubmit = async (e) => {
      e.preventDefault();
      const msg = $("#auth-msg");
      const username = $("#a-username").value.trim();
      const password = $("#a-password").value;
      const btn = form.querySelector("button[type=submit]");
      btn.disabled = true;
      try {
        if (mode === "setup") {
          const name = $("#a-name").value.trim();
          await api("/api/setup", { method: "POST", body: JSON.stringify({ username, name, password }) });
        } else {
          await api("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
        }
        location.reload();
      } catch (err) {
        showMsg(msg, err.message, "error");
        btn.disabled = false;
      }
    };
    $("#a-username").focus();
  }

  function showMsg(el, text, type) {
    el.style.display = "block";
    el.className = "msg " + (type || "info");
    el.textContent = text;
  }

  // ---------------- Theme ----------------
  function applyTheme() {
    const t = localStorage.getItem("nfi_theme") || "dark";
    document.documentElement.setAttribute("data-theme", t);
    const btn = $("#theme-btn");
    if (btn) btn.textContent = t === "dark" ? "☀️" : "🌙";
  }
  function toggleTheme() {
    const t = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    localStorage.setItem("nfi_theme", t);
    applyTheme();
  }

  // ---------------- Boot ----------------
  async function boot() {
    applyTheme();
    let status;
    try { status = await api("/api/status"); } catch (e) { return; }
    if (status.setup_required) { showAuth("setup"); return; }
    if (!status.authenticated) { showAuth("login"); return; }
    state.me = status.user;
    initPanel();
  }

  function initPanel() {
    $("#auth-screen").style.display = "none";
    $("#layout").style.display = "flex";
    $("#chip-name").textContent = state.me.name || state.me.username;
    $("#avatar").textContent = (state.me.name || state.me.username).charAt(0).toUpperCase();
    $("#chip-role").textContent = ROLE_FA[state.me.role] || state.me.role;

    $("#logout-btn").addEventListener("click", async () => {
      try { await api("/api/logout", { method: "POST", body: "{}" }); } catch (e) {}
      showAuth("login");
    });
    $("#modal-close").addEventListener("click", closeModal);
    $("#modal-overlay").addEventListener("click", (e) => { if (e.target === $("#modal-overlay")) closeModal(); });
    $("#mobile-menu").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
    $("#theme-btn").addEventListener("click", toggleTheme);
    $("#notif-btn").addEventListener("click", toggleNotifDrop);
    $("#notif-read").addEventListener("click", () => markNotifRead(true));
    document.addEventListener("click", (e) => {
      const drop = $("#notif-drop");
      if (drop && !drop.classList.contains("hidden") && !e.target.closest("#notif-wrap")) {
        drop.classList.add("hidden");
      }
    });

    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        switchView(btn.dataset.view);
        $("#sidebar").classList.remove("open");
      });
    });
    document.querySelectorAll(".nav-item[data-roles]").forEach((btn) => {
      const roles = (btn.dataset.roles || "").split(/\s+/);
      if (!roles.includes(state.me.role)) btn.style.display = "none";
    });

    $("#alerts-clear").addEventListener("click", () => {
      Object.keys(state.seenAlerts).forEach((k) => state.seenAlerts[k] = true);
      saveSeenAlerts();
      refreshAlertsPanel();
    });

    setInterval(() => {
      const el = $("#clock");
      if (el) el.textContent = new Date().toLocaleTimeString("fa-IR");
    }, 1000);

    loadAll();
    setInterval(() => { if (state.me && $("#layout").style.display !== "none") pollExtras(); }, 10000);
  }

  function loadSeen() {
    try {
      state.seenAlerts = JSON.parse(localStorage.getItem("nfi_seen_alerts") || "{}");
      state.seenWarnings = JSON.parse(localStorage.getItem("nfi_seen_warnings") || "{}");
    } catch (e) { state.seenAlerts = {}; state.seenWarnings = {}; }
  }
  function saveSeenAlerts() { localStorage.setItem("nfi_seen_alerts", JSON.stringify(state.seenAlerts)); }
  function saveSeenWarnings() { localStorage.setItem("nfi_seen_warnings", JSON.stringify(state.seenWarnings)); }

  // ---------------- View switching ----------------
  const TITLES = { dashboard: "داشبورد", games: "بازی‌ها", apps: "برنامه‌ها", projects: "پروژه‌ها", orders: "سفارش‌ها", invoices: "فاکتورها", team: "تیم", teams: "تیم‌ها", chat: "چت", manage: "مدیریت", settings: "تنظیمات" };

  function switchView(name) {
    chatPollGen++;
    state.activeView = name;
    state.mediaDetail = null;
    state.personDetail = null;
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
    $("#page-title").textContent = TITLES[name] || "";
    renderCurrent();
  }

  function renderCurrent() {
    if (state.personDetail) {
      renderPersonDetail($("#content"), state.personDetail);
      return;
    }
    const v = state.activeView;
    const content = $("#content");
    if (v === "dashboard") renderDashboard(content);
    else if (v === "games") renderMediaList(content, "games");
    else if (v === "apps") renderMediaList(content, "apps");
    else if (v === "projects") renderProjects(content);
    else if (v === "orders") renderOrders(content);
    else if (v === "invoices") renderInvoices(content);
    else if (v === "team") renderTeam(content);
    else if (v === "teams") renderTeams(content);
    else if (v === "chat") renderChat(content);
    else if (v === "manage") renderManage(content);
    else if (v === "settings") renderSettings(content);
  }

  function openDetail(type, id) { state.mediaDetail = { type, id }; renderCurrent(); }
  function backToList() { state.mediaDetail = null; renderCurrent(); }

  // ---------------- Data loading ----------------
  async function loadAll() {
    try {
      const wantPeople = canManagePeople();
      const reqs = [
        api("/api/users"), api("/api/games"), api("/api/apps"),
        api("/api/projects"), api("/api/orders"), api("/api/settings"),
        api("/api/invoices"), api("/api/channels"), api("/api/teams"),
      ];
      if (wantPeople) reqs.push(api("/api/people"));
      const r = await Promise.all(reqs);
      state.users = r[0].users || [];
      state.games = r[1].games || [];
      state.apps = r[2].apps || [];
      state.projects = r[3].projects || [];
      state.orders = r[4].orders || [];
      state.settings = r[5].settings || {};
      state.invoices = r[6].invoices || [];
      state.channels = r[7].channels || [];
      state.teams = r[8].teams || [];
      state.people = wantPeople ? (r[9].people || []) : [];
      renderCurrent();
      loadSeen();
      pollExtras();
    } catch (err) {
      if (err.status !== 401) toast(err.message, "error");
    }
  }

  async function reload() {
    try {
      const wantPeople = canManagePeople();
      const reqs = [
        api("/api/games"), api("/api/apps"), api("/api/projects"), api("/api/orders"),
        api("/api/invoices"), api("/api/channels"), api("/api/teams"),
      ];
      if (wantPeople) reqs.push(api("/api/people"));
      const r = await Promise.all(reqs);
      state.games = r[0].games || [];
      state.apps = r[1].apps || [];
      state.projects = r[2].projects || [];
      state.orders = r[3].orders || [];
      state.invoices = r[4].invoices || [];
      state.channels = r[5].channels || [];
      state.teams = r[6].teams || [];
      state.people = wantPeople ? (r[7].people || []) : [];
      renderCurrent();
    } catch (err) { if (err.status !== 401) toast(err.message, "error"); }
  }

  // ---------------- Notifications ----------------
  async function pollExtras() {
    if (!state.me) return;
    try {
      const [alertsR, warnR, notifR] = await Promise.all([
        api("/api/alerts"), api("/api/warnings"), api("/api/notifications"),
      ]);
      state.alertsCache = alertsR.alerts || [];
      state.alertsCache.forEach((a) => {
        if (state.seenAlerts[a.id] === undefined || state.seenAlerts[a.id] === null) state.seenAlerts[a.id] = false;
      });
      refreshAlertsPanel();
      state.warnings = warnR.warnings || [];
      state.notifications = notifR.notifications || [];
      state.notifUnread = notifR.unread || 0;
      renderNotifBadge();
      renderWarnings();
    } catch (e) {}
  }

  function renderNotifBadge() {
    const badge = $("#notif-badge");
    if (!badge) return;
    badge.textContent = state.notifUnread ? state.notifUnread : "";
    badge.style.display = state.notifUnread ? "flex" : "none";
  }

  function toggleNotifDrop() {
    const drop = $("#notif-drop");
    if (!drop) return;
    if (drop.classList.contains("hidden")) {
      $("#notif-list").innerHTML = state.notifications.length ? state.notifications.map((n) => `
        <div class="notif-item ${n.read ? "" : "unread"}">
          <div class="notif-text">${esc(n.text)}</div>
          <div class="notif-meta">${fmtTime(n.at)}</div>
        </div>`).join("") : `<div class="empty-state" style="padding:24px"><p>نوتیفیکیشنی نیست</p></div>`;
      drop.classList.remove("hidden");
    } else {
      drop.classList.add("hidden");
    }
  }

  async function markNotifRead(all) {
    try {
      await api("/api/notifications/read", { method: "POST", body: JSON.stringify({ all: !!all }) });
      state.notifUnread = 0;
      renderNotifBadge();
      pollExtras();
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Modal ----------------
  function openModal(title, bodyHtml) {
    $("#modal-title").textContent = title;
    $("#modal-body").innerHTML = bodyHtml;
    $("#modal-overlay").style.display = "flex";
  }
  function closeModal() { $("#modal-overlay").style.display = "none"; }

  function selectOptions(values, selected, map) {
    return values.map((v) => `<option value="${v}"${v === selected ? " selected" : ""}>${map[v] || v}</option>`).join("");
  }

  // ---------------- Dashboard ----------------
  function renderDashboard(c) {
    const cur = state.settings.currency || "$";
    const sum = (arr, k) => arr.reduce((s, x) => s + (parseFloat(x[k]) || 0), 0);
    const pendingGames = state.games.filter((g) => g.status === "pending").length;
    const pendingApps = state.apps.filter((a) => a.status === "pending").length;
    const card = (label, value, sub, view) => `
      <div class="stat-card" role="button" onclick="NFI.go('${view}')" style="cursor:pointer">
        <div class="stat-label">${label}</div>
        <div class="stat-value">${value}</div>
        <div class="stat-sub">${sub || ""}</div>
      </div>`;
    const pendNote = isApprover() ? (pendingGames + pendingApps ? ` (${pendingGames + pendingApps} در انتظار)` : "") : "";

    c.innerHTML = `
      <div class="stats-grid">
        ${card("تعداد بازی‌ها", state.games.length, "بودجه: " + fmtMoney(sum(state.games, "budget"), cur) + (isApprover() && pendingGames ? ` · ${pendingGames} در انتظار` : ""), "games")}
        ${card("تعداد برنامه‌ها", state.apps.length, "بودجه: " + fmtMoney(sum(state.apps, "budget"), cur) + (isApprover() && pendingApps ? ` · ${pendingApps} در انتظار` : ""), "apps")}
        ${card("پروژه‌ها", state.projects.length, "بودجه: " + fmtMoney(sum(state.projects, "budget"), cur), "projects")}
        ${card("سفارش‌ها", state.orders.length, "", "orders")}
        ${card("فاکتورها", state.invoices.length, pendNote || "", "invoices")}
      </div>

      <div class="section-title">
        <h2>محیط سامانه</h2>
        <span class="muted">خوش آمدید، ${esc(state.me.name || state.me.username)}</span>
      </div>
      <div class="quick-links">
        <button class="btn btn-primary" onclick="NFI.go('games')">مدیریت بازی‌ها</button>
        <button class="btn" onclick="NFI.go('apps')">مدیریت برنامه‌ها</button>
        <button class="btn" onclick="NFI.go('projects')">پروژه‌ها</button>
        <button class="btn" onclick="NFI.go('orders')">سفارش‌ها</button>
        <button class="btn" onclick="NFI.go('invoices')">فاکتورها</button>
        <button class="btn" onclick="NFI.go('team')">تیم و کاربران</button>
        <button class="btn" onclick="NFI.go('teams')">تیم‌ها</button>
        <button class="btn" onclick="NFI.go('chat')">چت</button>
        ${canViewDoc() ? `<button class="btn btn-success" onclick="NFI.go('manage')">مدیریت</button>` : ""}
        ${canAlert() ? `<button class="btn" onclick="NFI.sendAlert()">ارسال الرت</button>` : ""}
      </div>
    `;
  }

  // ---------------- Games / Apps ----------------
  const MEDIA_META = { games: { title: "بازی‌ها", item: "بازی", endpoint: "/api/games", stateKey: "games" }, apps: { title: "برنامه‌ها", item: "برنامه", endpoint: "/api/apps", stateKey: "apps" } };

  function mediaForm(item, type) {
    item = item || {};
    const statusSel = isApprover() ? `
      <div class="field full">
        <label>وضعیت</label>
        <select id="m-status">${selectOptions(["approved", "pending"], item.status || "approved", { approved: "تایید شده", pending: "در انتظار تایید" })}</select>
      </div>` : "";
    return `
      <form id="media-form" onsubmit="NFI.saveMedia(event,'${type}')">
        <div class="form-grid">
          <div class="field full"><label>نام *</label><input type="text" id="m-name" required value="${esc(item.name || "")}"></div>
          <div class="field"><label>ورژن فعلی *</label><input type="text" id="m-version" required value="${esc(item.version || "")}" placeholder="v1.0.0"></div>
          <div class="field"><label>تاریخ ساخت *</label><input type="date" id="m-build" required value="${esc(item.build_date || "")}"></div>
          <div class="field full"><label>بودجه تعیین‌شده *</label><input type="text" id="m-budget" required value="${esc(item.budget || "")}" placeholder="مثلاً: 150000"></div>
          ${statusSel}
        </div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
          <button type="submit" class="btn btn-primary">ذخیره</button>
        </div>
      </form>`;
  }

  function renderMediaList(c, type) {
    const meta = MEDIA_META[type];
    const items = state[meta.stateKey];
    const cur = state.settings.currency || "$";
    c.innerHTML = `
      <div class="section-title">
        <h2>${meta.title} (${items.length})</h2>
        ${canEdit() ? `<button class="btn btn-primary btn-sm" onclick="NFI.addMedia('${type}')">+ افزودن ${meta.item}</button>` : ""}
      </div>
      <div class="card">
        ${items.length ? `<div class="table-wrap"><table>
          <thead><tr><th>نام</th><th>ورژن</th><th>تاریخ ساخت</th><th>بودجه</th><th>تعداد نسخه</th><th>وضعیت</th><th>عملیات</th></tr></thead>
          <tbody>
            ${items.map((it) => mediaRow(it, type, cur)).join("")}
          </tbody>
        </table></div>` : `<div class="empty-state"><p>هنوز ${meta.item}ای ثبت نشده است.</p></div>`}
      </div>`;
  }

  function mediaRow(it, type, cur) {
    const pending = it.status === "pending";
    return `
      <tr class="clickable" onclick="NFI.openDetail('${type}','${it.id}')">
        <td><strong>${esc(it.name)}</strong></td>
        <td class="mono">${esc(it.version) || "—"}</td>
        <td>${esc(it.build_date) || "—"}</td>
        <td>${fmtMoney(it.budget, cur)}</td>
        <td><span class="badge ${(it.versions || []).length ? "green" : "user"}">${(it.versions || []).length}</span></td>
        <td>${pending ? '<span class="badge amber">در انتظار</span>' : '<span class="badge green">تایید شده</span>'}</td>
        <td><div class="row-actions">
          ${canEdit() && pending && isApprover() ? `<button class="btn btn-success btn-sm" onclick="event.stopPropagation();NFI.approveMedia('${type}','${it.id}')">تایید</button>` : ""}
          ${canEdit() ? `<button class="btn btn-danger btn-sm" onclick="event.stopPropagation();NFI.deleteMedia('${type}','${it.id}','${esc(it.name)}')">حذف</button>` : ""}
        </div></td>
      </tr>`;
  }

  function renderDetail(c, type) {
    const meta = MEDIA_META[type];
    const item = state[meta.stateKey].find((x) => x.id === state.mediaDetail.id);
    if (!item) { backToList(); return; }
    const cur = state.settings.currency || "$";
    const versions = item.versions || [];
    const pending = item.status === "pending";
    const canTouch = canEdit() && (!pending || isApprover());
    c.innerHTML = `
      <div class="flex" style="margin-bottom:14px">
        <button class="btn btn-ghost btn-sm" onclick="NFI.back()">← برگشت</button>
        <h2 style="margin:0">${esc(item.name)}</h2>
        ${pending ? '<span class="badge amber">در انتظار تایید</span>' : '<span class="badge green">تایید شده</span>'}
        ${canTouch ? `
          <div class="row-actions" style="margin-inline-start:auto">
            <button class="btn btn-sm" onclick="NFI.editMedia('${type}','${item.id}')">ویرایش</button>
            <button class="btn btn-danger btn-sm" onclick="NFI.deleteMedia('${type}','${item.id}','${esc(item.name)}')">حذف ${meta.item}</button>
          </div>` : ""}
        ${canEdit() && pending && isApprover() ? `<button class="btn btn-success btn-sm" onclick="NFI.approveMedia('${type}','${item.id}')">تایید نهایی</button>` : ""}
      </div>

      <div class="stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr))">
        <div class="stat-card"><div class="stat-label">ورژن فعلی</div><div class="stat-value mono" style="font-size:20px">${esc(item.version) || "—"}</div></div>
        <div class="stat-card"><div class="stat-label">تاریخ ساخت</div><div class="stat-value" style="font-size:20px">${esc(item.build_date) || "—"}</div></div>
        <div class="stat-card"><div class="stat-label">بودجه</div><div class="stat-value" style="font-size:20px">${fmtMoney(item.budget, cur)}</div></div>
        <div class="stat-card"><div class="stat-label">نسخه‌های ساخته‌شده</div><div class="stat-value" style="font-size:20px">${versions.length}</div></div>
      </div>

      <div class="section-title"><h2>نسخه‌های ساخته شده</h2></div>
      <div class="card">
        ${versions.length ? `<div class="table-wrap"><table>
          <thead><tr><th>ورژن</th><th>تاریخ ساخت</th><th>توسط</th><th>یادداشت</th>${canEdit() ? "<th></th>" : ""}</tr></thead>
          <tbody>
            ${versions.map((v) => `
              <tr>
                <td class="mono"><strong>${esc(v.version)}</strong></td>
                <td>${esc(v.build_date)}</td>
                <td>${esc(v.created_by || "")}</td>
                <td class="muted">${esc(v.notes || "")}</td>
                ${canEdit() && (!pending || isApprover()) ? `<td><button class="btn btn-danger btn-sm" onclick="NFI.deleteVersion('${type}','${item.id}','${v.id}')">حذف</button></td>` : ""}
              </tr>`).join("")}
          </tbody>
        </table></div>` : `<div class="empty-state"><p>هنوز نسخه‌ای ساخته نشده است.</p></div>`}
      </div>

      ${canEdit() && (!pending || isApprover()) ? `
        <div class="card">
          <div class="card-head"><h3>ساخت نسخه جدید</h3></div>
          <form onsubmit="NFI.addVersion(event,'${type}','${item.id}')">
            <div class="form-grid">
              <div class="field"><label>شماره ورژن *</label><input type="text" id="v-version" required placeholder="v1.1.0"></div>
              <div class="field"><label>تاریخ ساخت *</label><input type="date" id="v-build" required></div>
              <div class="field full"><label>یادداشت نسخه (اختیاری)</label><textarea id="v-notes" placeholder="تغییرات این نسخه..."></textarea></div>
            </div>
            <div class="form-actions"><button type="submit" class="btn btn-primary">ساخت نسخه</button></div>
          </form>
        </div>` : ""}
    `;
  }

  function showAddMedia(type) { state.editingId = null; openModal("افزودن " + MEDIA_META[type].item, mediaForm(null, type)); }
  function editMedia(type, id) {
    const item = state[MEDIA_META[type].stateKey].find((x) => x.id === id);
    if (!item) { toast("مورد یافت نشد", "error"); return; }
    state.editingId = id;
    openModal("ویرایش " + MEDIA_META[type].item, mediaForm(item, type));
  }
  async function saveMedia(e, type) {
    e.preventDefault();
    const meta = MEDIA_META[type];
    const body = {
      name: $("#m-name").value.trim(), version: $("#m-version").value.trim(),
      build_date: $("#m-build").value, budget: $("#m-budget").value.trim(),
    };
    if (isApprover() && $("#m-status")) body.status = $("#m-status").value;
    try {
      if (state.editingId) await api(`${meta.endpoint}/${state.editingId}`, { method: "PUT", body: JSON.stringify(body) });
      else await api(meta.endpoint, { method: "POST", body: JSON.stringify(body) });
      state.editingId = null;
      closeModal();
      toast("ذخیره شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function approveMedia(type, id) {
    try {
      await api(`${MEDIA_META[type].endpoint}/${id}`, { method: "PUT", body: JSON.stringify({ status: "approved" }) });
      toast("تایید شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function deleteMedia(type, id, name) {
    if (!confirm(`آیا از حذف «${name}» مطمئن هستید؟`)) return;
    try {
      await api(`${MEDIA_META[type].endpoint}/${id}`, { method: "DELETE", body: "{}" });
      toast("حذف شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function addVersion(e, type, id) {
    e.preventDefault();
    try {
      await api(`${MEDIA_META[type].endpoint}/${id}/versions`, {
        method: "POST",
        body: JSON.stringify({ version: $("#v-version").value.trim(), build_date: $("#v-build").value, notes: $("#v-notes").value.trim() }),
      });
      toast("نسخه ساخته شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function deleteVersion(type, id, vid) {
    if (!confirm("این نسخه حذف شود؟")) return;
    try {
      await api(`${MEDIA_META[type].endpoint}/${id}/versions/${vid}`, { method: "DELETE", body: "{}" });
      toast("نسخه حذف شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Projects ----------------
  function projectForm(pr) {
    pr = pr || {};
    return `
      <form id="project-form" onsubmit="NFI.saveProject(event)">
        <div class="form-grid">
          <div class="field full"><label>نام پروژه *</label><input type="text" id="p-name" required value="${esc(pr.name || "")}"></div>
          <div class="field full"><label>بودجه *</label><input type="text" id="p-budget" required value="${esc(pr.budget || "")}"></div>
          <div class="field"><label>وضعیت *</label><select id="p-status" required>${selectOptions(Object.keys(PROJECT_STATUS_FA), pr.status || "active", PROJECT_STATUS_FA)}</select></div>
          <div class="field"><label>تاریخ شروع *</label><input type="date" id="p-start" required value="${esc(pr.start_date || "")}"></div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
          <button type="submit" class="btn btn-primary">ذخیره</button>
        </div>
      </form>`;
  }

  function renderProjects(c) {
    const cur = state.settings.currency || "$";
    c.innerHTML = `
      <div class="section-title">
        <h2>پروژه‌ها (${state.projects.length})</h2>
        ${canEdit() ? `<button class="btn btn-primary btn-sm" onclick="NFI.showAddProject()">+ افزودن پروژه</button>` : ""}
      </div>
      <div class="card">
        ${state.projects.length ? `<div class="table-wrap"><table>
          <thead><tr><th>نام</th><th>بودجه</th><th>وضعیت</th><th>تاریخ شروع</th><th>عملیات</th></tr></thead>
          <tbody>
            ${state.projects.map((p) => `
              <tr>
                <td><strong>${esc(p.name)}</strong></td>
                <td>${fmtMoney(p.budget, cur)}</td>
                <td><span class="badge ${p.status === "active" ? "green" : p.status === "done" ? "admin" : p.status === "pending" ? "amber" : "red"}">${PROJECT_STATUS_FA[p.status] || esc(p.status)}</span></td>
                <td>${esc(p.start_date) || "—"}</td>
                <td><div class="row-actions">
                  ${canEdit() ? `<button class="btn btn-sm" onclick="NFI.editProject('${p.id}')">ویرایش</button>
                  <button class="btn btn-danger btn-sm" onclick="NFI.deleteProject('${p.id}','${esc(p.name)}')">حذف</button>` : '<span class="muted">—</span>'}
                </div></td>
              </tr>`).join("")}
          </tbody>
        </table></div>` : `<div class="empty-state"><p>هنوز پروژه‌ای ثبت نشده است.</p></div>`}
      </div>`;
  }

  function showAddProject() { state.editingId = null; openModal("افزودن پروژه", projectForm()); }
  function editProject(id) {
    const pr = state.projects.find((x) => x.id === id);
    if (!pr) return;
    state.editingId = id;
    openModal("ویرایش پروژه", projectForm(pr));
  }
  async function saveProject(e) {
    e.preventDefault();
    const body = JSON.stringify({ name: $("#p-name").value.trim(), budget: $("#p-budget").value.trim(), status: $("#p-status").value, start_date: $("#p-start").value });
    try {
      if (state.editingId) await api("/api/projects/" + state.editingId, { method: "PUT", body });
      else await api("/api/projects", { method: "POST", body });
      state.editingId = null;
      closeModal();
      toast("پروژه ذخیره شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function deleteProject(id, name) {
    if (!confirm(`آیا از حذف پروژه «${name}» مطمئن هستید؟`)) return;
    try {
      await api("/api/projects/" + id, { method: "DELETE", body: "{}" });
      toast("حذف شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Orders ----------------
  function orderForm(o) {
    o = o || {};
    return `
      <form id="order-form" onsubmit="NFI.saveOrder(event)">
        <div class="form-grid">
          <div class="field full"><label>نام سفارش *</label><input type="text" id="o-name" required value="${esc(o.name || "")}"></div>
          <div class="field full"><label>نوع سفارش *</label><select id="o-type" required>${selectOptions(Object.keys(ORDER_TYPE_FA), o.type || "site", ORDER_TYPE_FA)}</select></div>
          <div class="field"><label>هزینه اصلی *</label><input type="text" id="o-main" required value="${esc(o.main_cost || "")}"></div>
          <div class="field"><label>هزینه ساخت *</label><input type="text" id="o-build" required value="${esc(o.build_cost || "")}"></div>
          <div class="field"><label>سود ناخالص *</label><input type="text" id="o-gross" required value="${esc(o.gross_profit || "")}"></div>
          <div class="field"><label>سود خالص *</label><input type="text" id="o-net" required value="${esc(o.net_profit || "")}"></div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
          <button type="submit" class="btn btn-primary">ذخیره</button>
        </div>
      </form>`;
  }

  function renderOrders(c) {
    const cur = state.settings.currency || "$";
    const sum = (k) => state.orders.reduce((s, x) => s + (parseFloat(x[k]) || 0), 0);
    c.innerHTML = `
      <div class="section-title">
        <h2>سفارش‌ها (${state.orders.length})</h2>
        ${canEdit() ? `<button class="btn btn-primary btn-sm" onclick="NFI.showAddOrder()">+ افزودن سفارش</button>` : ""}
      </div>
      <div class="stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr))">
        <div class="stat-card"><div class="stat-label">سود خالص کل</div><div class="stat-value">${fmtMoney(sum("net_profit"), cur)}</div></div>
        <div class="stat-card"><div class="stat-label">سود ناخالص کل</div><div class="stat-value">${fmtMoney(sum("gross_profit"), cur)}</div></div>
        <div class="stat-card"><div class="stat-label">هزینه ساخت کل</div><div class="stat-value">${fmtMoney(sum("build_cost"), cur)}</div></div>
        <div class="stat-card"><div class="stat-label">هزینه اصلی کل</div><div class="stat-value">${fmtMoney(sum("main_cost"), cur)}</div></div>
      </div>
      <div class="card">
        ${state.orders.length ? `<div class="table-wrap"><table>
          <thead><tr><th>نام</th><th>نوع</th><th>هزینه اصلی</th><th>هزینه ساخت</th><th>سود ناخالص</th><th>سود خالص</th><th>عملیات</th></tr></thead>
          <tbody>
            ${state.orders.map((o) => `
              <tr>
                <td><strong>${esc(o.name)}</strong></td>
                <td><span class="badge admin">${ORDER_TYPE_FA[o.type] || esc(o.type)}</span></td>
                <td>${fmtMoney(o.main_cost, cur)}</td>
                <td>${fmtMoney(o.build_cost, cur)}</td>
                <td>${fmtMoney(o.gross_profit, cur)}</td>
                <td><span class="badge green">${fmtMoney(o.net_profit, cur)}</span></td>
                <td><div class="row-actions">
                  ${canEdit() ? `<button class="btn btn-sm" onclick="NFI.editOrder('${o.id}')">ویرایش</button>
                  <button class="btn btn-danger btn-sm" onclick="NFI.deleteOrder('${o.id}','${esc(o.name)}')">حذف</button>` : '<span class="muted">—</span>'}
                </div></td>
              </tr>`).join("")}
          </tbody>
        </table></div>` : `<div class="empty-state"><p>هنوز سفارشی ثبت نشده است.</p></div>`}
      </div>`;
  }

  function showAddOrder() { state.editingId = null; openModal("افزودن سفارش", orderForm()); }
  function editOrder(id) {
    const o = state.orders.find((x) => x.id === id);
    if (!o) return;
    state.editingId = id;
    openModal("ویرایش سفارش", orderForm(o));
  }
  async function saveOrder(e) {
    e.preventDefault();
    const body = JSON.stringify({ name: $("#o-name").value.trim(), type: $("#o-type").value, main_cost: $("#o-main").value.trim(), build_cost: $("#o-build").value.trim(), gross_profit: $("#o-gross").value.trim(), net_profit: $("#o-net").value.trim() });
    try {
      if (state.editingId) await api("/api/orders/" + state.editingId, { method: "PUT", body });
      else await api("/api/orders", { method: "POST", body });
      state.editingId = null;
      closeModal();
      toast("سفارش ذخیره شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function deleteOrder(id, name) {
    if (!confirm(`آیا از حذف سفارش «${name}» مطمئن هستید؟`)) return;
    try {
      await api("/api/orders/" + id, { method: "DELETE", body: "{}" });
      toast("حذف شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Invoices ----------------
  function invoiceForm(inv) {
    inv = inv || {};
    return `
      <form id="invoice-form" onsubmit="NFI.saveInvoice(event)">
        <div class="form-grid">
          <div class="field full"><label>نوع فاکتور</label>
            <select id="i-type">
              <option value="sale"${inv.inv_type === "sale" ? " selected" : ""}>فروش</option>
              <option value="buy"${inv.inv_type === "buy" ? " selected" : ""}>خرید</option>
            </select>
          </div>
          <div class="field full"><label>نام کالا یا نرم‌افزار *</label><input type="text" id="i-name" required value="${esc(inv.item_name || "")}" placeholder="مثلاً: نرم‌افزار حسابداری / 10 عدد ماوس"></div>
          <div class="field"><label>تعداد *</label><input type="number" id="i-qty" required min="1" step="1" value="${esc(inv.quantity || 1)}"></div>
          <div class="field"><label>قیمت واحد *</label><input type="number" id="i-price" required min="0.01" step="0.01" value="${esc(inv.unit_price || "")}"></div>
          <div class="field full"><label>هزینه اصلی (محاسبه خودکار)</label>
            <div class="total-box" id="i-total">—</div>
          </div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
          <button type="submit" class="btn btn-primary">ثبت و ارسال برای تایید</button>
        </div>
      </form>`;
  }

  function calcInvoiceTotal() {
    const q = parseFloat($("#i-qty")?.value) || 0;
    const p = parseFloat($("#i-price")?.value) || 0;
    const el = $("#i-total");
    if (el) el.textContent = fmtMoney(q * p, state.settings.currency || "$");
  }

  function renderInvoices(c) {
    const cur = state.settings.currency || "$";
    const cnt = (s) => state.invoices.filter((x) => x.status === s).length;
    c.innerHTML = `
      <div class="section-title">
        <h2>فاکتورها (${state.invoices.length})</h2>
        ${canInvoice() ? `<button class="btn btn-primary btn-sm" onclick="NFI.showAddInvoice()">+ ثبت فاکتور</button>` : ""}
      </div>
      <div class="stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(170px,1fr))">
        <div class="stat-card"><div class="stat-label">در انتظار تایید</div><div class="stat-value" style="font-size:22px;color:var(--amber)">${cnt("pending")}</div></div>
        <div class="stat-card"><div class="stat-label">تایید شده</div><div class="stat-value" style="font-size:22px;color:var(--green)">${cnt("approved")}</div></div>
        <div class="stat-card"><div class="stat-label">رد شده</div><div class="stat-value" style="font-size:22px;color:var(--red)">${cnt("rejected")}</div></div>
      </div>
      <div class="card">
        ${state.invoices.length ? `<div class="table-wrap"><table>
          <thead><tr><th>نوع</th><th>نام کالا / نرم‌افزار</th><th>تعداد</th><th>قیمت واحد</th><th>هزینه اصلی</th><th>وضعیت</th><th>ثبت‌کننده</th><th>عملیات</th></tr></thead>
          <tbody>
            ${state.invoices.map((inv) => invoiceRow(inv, cur)).join("")}
          </tbody>
        </table></div>` : `<div class="empty-state"><p>هنوز فاکتوری ثبت نشده است.</p></div>`}
      </div>`;
  }

  function invoiceRow(inv, cur) {
    const mine = inv.created_by === state.me.username;
    const canDecide = isApprover();
    const canEdit = (mine && inv.status === "pending") || isAdmin();
    const canDelete = mine && inv.status === "pending" || isAdmin();
    const stBadge = inv.status === "approved" ? '<span class="badge green">تایید شده</span>' :
                    inv.status === "rejected" ? '<span class="badge red">رد شده</span>' :
                    '<span class="badge amber">در انتظار تایید</span>';
    return `
      <tr>
        <td><span class="badge ${inv.inv_type === "sale" ? "admin" : "user"}">${INVOICE_TYPE_FA[inv.inv_type] || esc(inv.inv_type)}</span></td>
        <td><strong>${esc(inv.item_name)}</strong></td>
        <td>${inv.quantity}</td>
        <td>${fmtMoney(inv.unit_price, cur)}</td>
        <td><strong>${fmtMoney(inv.total, cur)}</strong></td>
        <td>${stBadge}</td>
        <td><span class="muted">${esc(inv.created_by_name || inv.created_by)}</span></td>
        <td><div class="row-actions">
          ${canDecide && inv.status === "pending" ? `
            <button class="btn btn-success btn-sm" onclick="NFI.decideInvoice('${inv.id}','approved')">تایید</button>
            <button class="btn btn-danger btn-sm" onclick="NFI.decideInvoice('${inv.id}','rejected')">رد</button>` : ""}
          ${canEdit ? `<button class="btn btn-sm" onclick="NFI.editInvoice('${inv.id}')">ویرایش</button>` : ""}
          ${canDelete ? `<button class="btn btn-danger btn-sm" onclick="NFI.deleteInvoice('${inv.id}')">حذف</button>` : ""}
        </div></td>
      </tr>`;
  }

  function showAddInvoice() {
    state.editingId = null;
    openModal("ثبت فاکتور", invoiceForm());
    setTimeout(() => {
      const fmt = () => calcInvoiceTotal();
      const a = $("#i-qty"); const b = $("#i-price");
      if (a) a.addEventListener("input", fmt);
      if (b) b.addEventListener("input", fmt);
      fmt();
    }, 10);
  }
  function editInvoice(id) {
    const inv = state.invoices.find((x) => x.id === id);
    if (!inv) return;
    state.editingId = id;
    openModal("ویرایش فاکتور", invoiceForm(inv));
    setTimeout(() => {
      const fmt = () => calcInvoiceTotal();
      const a = $("#i-qty"); const b = $("#i-price");
      if (a) a.addEventListener("input", fmt);
      if (b) b.addEventListener("input", fmt);
      fmt();
    }, 10);
  }
  async function saveInvoice(e) {
    e.preventDefault();
    const body = JSON.stringify({
      inv_type: $("#i-type").value, item_name: $("#i-name").value.trim(),
      quantity: $("#i-qty").value, unit_price: $("#i-price").value,
    });
    try {
      if (state.editingId) await api("/api/invoices/" + state.editingId, { method: "PUT", body });
      else await api("/api/invoices", { method: "POST", body });
      state.editingId = null;
      closeModal();
      toast("فاکتور ثبت شد و در انتظار تایید است", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function decideInvoice(id, status) {
    if (!confirm(status === "approved" ? "این فاکتور تایید شود؟" : "این فاکتور رد شود؟")) return;
    try {
      await api("/api/invoices/" + id, { method: "PUT", body: JSON.stringify({ status }) });
      toast("انجام شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function deleteInvoice(id) {
    if (!confirm("این فاکتور حذف شود؟")) return;
    try {
      await api("/api/invoices/" + id, { method: "DELETE", body: "{}" });
      toast("حذف شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Team ----------------
  function renderTeam(c) {
    const roles = creatableRoles(state.me.role);
    c.innerHTML = `
      <div class="section-title">
        <h2>تیم و هم‌تیمی‌ها (${state.users.length})</h2>
        ${roles.length ? `<button class="btn btn-primary btn-sm" onclick="NFI.showAddUser()">+ افزودن هم‌تیمی</button>` : ""}
      </div>
      <div class="card">
        ${state.users.length ? `<div class="table-wrap"><table>
          <thead><tr><th>نام</th><th>نام کاربری</th><th>نقش</th><th>اختیارات</th><th>وضعیت</th><th>عملیات</th></tr></thead>
          <tbody>
            ${state.users.map((u) => teamRow(u)).join("")}
          </tbody>
        </table></div>` : `<div class="empty-state"><p>کاربری ثبت نشده است.</p></div>`}
      </div>`;
  }

  function teamRow(u) {
    const perms = [];
    if (u.mod_chat) perms.push("مدیریت چت");
    if (u.can_warn) perms.push("ارسال اخطار");
    const permText = perms.length ? perms.map((p) => `<span class="badge amber">${p}</span>`).join(" ") : '<span class="muted">—</span>';
    return `
      <tr>
        <td><strong>${esc(u.name || u.username)}</strong> ${u.username === state.me.username ? '<span class="badge green">شما</span>' : ""}</td>
        <td class="mono">${esc(u.username)}</td>
        <td><span class="badge ${u.role === "admin" ? "admin" : u.role === "manager" ? "amber" : u.role === "developer" ? "green" : u.role === "employee" ? "red" : "user"}">${ROLE_FA[u.role] || esc(u.role)}</span></td>
        <td>${permText}</td>
        <td>${u.banned ? '<span class="badge red">بن شده</span>' : '<span class="badge green">فعال</span>'}</td>
        <td><div class="row-actions">
          ${u.username === state.me.username ? '<span class="muted">—</span>' : ""}
          ${canManageUser(u) ? `<button class="btn btn-sm" onclick="NFI.editUser('${esc(u.username)}')">ویرایش</button>` : ""}
          ${canManageUser(u) && isApprover() ? `<button class="btn btn-sm" onclick="NFI.resetUserPw('${esc(u.username)}')">تعویض رمز</button>` : ""}
          ${canManageUser(u) && isApprover() ? `<button class="btn ${u.banned ? "btn-success" : "btn-danger"} btn-sm" onclick="NFI.toggleBan('${esc(u.username)}',${u.banned ? 0 : 1},'${esc(u.name || u.username)}')">${u.banned ? "رفع بن" : "بن"}</button>` : ""}
          ${canManageUser(u) ? `<button class="btn btn-danger btn-sm" onclick="NFI.deleteUser('${esc(u.username)}','${esc(u.name || u.username)}')">حذف</button>` : ""}
        </div></td>
      </tr>`;
  }

  function userForm() {
    const roles = creatableRoles(state.me.role);
    const adminExtras = isAdmin() ? `
      <div class="field">
        <label><input type="checkbox" id="u-mod" class="check-inline"> مدیریت چت (دیدن چت‌های هم‌تیمی‌ها)</label>
      </div>
      <div class="field">
        <label><input type="checkbox" id="u-warn" class="check-inline"> ارسال اخطار</label>
      </div>` : "";
    return `
      <form id="user-form" onsubmit="NFI.saveUser(event)">
        <div class="field"><label>نام و نام خانوادگی *</label><input type="text" id="u-name" required></div>
        <div class="field"><label>نام کاربری *</label><input type="text" id="u-username" required></div>
        <div class="field"><label>رمز عبور * (حداقل ۶ کاراکتر)</label><input type="password" id="u-pass" required minlength="6"></div>
        <div class="field"><label>نقش</label><select id="u-role">${roles.map((r) => `<option value="${r}">${ROLE_FA[r]}</option>`).join("")}</select></div>
        ${adminExtras}
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
          <button type="submit" class="btn btn-primary">ایجاد اکانت</button>
        </div>
      </form>`;
  }

  function showAddUser() { openModal("افزودن هم‌تیمی", userForm()); }
  async function saveUser(e) {
    e.preventDefault();
    const body = {
      username: $("#u-username").value.trim(), name: $("#u-name").value.trim(),
      password: $("#u-pass").value, role: $("#u-role").value,
    };
    if (isAdmin()) { body.mod_chat = !!$("#u-mod")?.checked; body.can_warn = !!$("#u-warn")?.checked; }
    try {
      await api("/api/users", { method: "POST", body: JSON.stringify(body) });
      closeModal();
      toast("اکانت ساخته شد", "success");
      const u = await api("/api/users");
      state.users = u.users || [];
      renderCurrent();
    } catch (err) { toast(err.message, "error"); }
  }

  function editUser(username) {
    const u = state.users.find((x) => x.username === username);
    if (!u) return;
    const roles = creatableRoles(state.me.role);
    const adminExtras = isAdmin() ? `
      <div class="field">
        <label><input type="checkbox" id="ue-mod" class="check-inline" ${u.mod_chat ? "checked" : ""}> مدیریت چت (دیدن چت‌های هم‌تیمی‌ها)</label>
      </div>
      <div class="field">
        <label><input type="checkbox" id="ue-warn" class="check-inline" ${u.can_warn ? "checked" : ""}> ارسال اخطار</label>
      </div>` : "";
    openModal("ویرایش هم‌تیمی", `
      <form id="user-edit-form" onsubmit="NFI.saveUserEdit(event,'${esc(username)}')">
        <div class="field"><label>نام و نام خانوادگی</label><input type="text" id="ue-name" required value="${esc(u.name || u.username)}"></div>
        <div class="field"><label>نقش</label>
          <select id="ue-role">${roles.map((r) => `<option value="${r}"${r === u.role ? " selected" : ""}>${ROLE_FA[r]}</option>`).join("")}</select>
        </div>
        ${adminExtras}
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
          <button type="submit" class="btn btn-primary">ذخیره</button>
        </div>
      </form>`);
  }
  async function saveUserEdit(e, username) {
    e.preventDefault();
    const body = { name: $("#ue-name").value.trim(), role: $("#ue-role").value };
    if (isAdmin()) { body.mod_chat = !!$("#ue-mod")?.checked; body.can_warn = !!$("#ue-warn")?.checked; }
    try {
      await api("/api/users/" + encodeURIComponent(username), { method: "PUT", body: JSON.stringify(body) });
      closeModal();
      toast("ذخیره شد", "success");
      const u = await api("/api/users");
      state.users = u.users || [];
      renderCurrent();
    } catch (err) { toast(err.message, "error"); }
  }

  async function resetUserPw(username) {
    const newPw = prompt("رمز عبور جدید برای «" + username + "» (حداقل ۶ کاراکتر):");
    if (!newPw) return;
    try {
      await api("/api/reset-password", { method: "POST", body: JSON.stringify({ username, new: newPw }) });
      toast("رمز عبور تغییر کرد", "success");
    } catch (err) { toast(err.message, "error"); }
  }

  async function toggleBan(username, ban, name) {
    const action = ban ? "بن" : "رفع بن";
    if (!confirm(`${action} کاربر «${name}»؟`)) return;
    try {
      await api("/api/users/" + encodeURIComponent(username), { method: "PUT", body: JSON.stringify({ banned: !!ban }) });
      toast("انجام شد", "success");
      const u = await api("/api/users");
      state.users = u.users || [];
      renderCurrent();
    } catch (err) { toast(err.message, "error"); }
  }

  async function deleteUser(username, name) {
    if (!confirm(`آیا از حذف کاربر «${name}» مطمئن هستید؟`)) return;
    try {
      await api("/api/users/" + encodeURIComponent(username), { method: "DELETE", body: "{}" });
      toast("حذف شد", "success");
      const u = await api("/api/users");
      state.users = u.users || [];
      renderCurrent();
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Chat (اصلی + تیم‌ها) ----------------
  function chatList() {
    const list = [{ kind: "main", id: null, title: "چت اصلی" }];
    (state.teams || []).forEach((t) => {
      let allowed = isApprover();
      if (!allowed) allowed = (t.members || []).some((m) => m.username === state.me.username);
      if (allowed) list.push({ kind: "team", id: t.id, title: "تیم: " + t.name });
    });
    return list;
  }

  function chatSideHtml() {
    const sel = state.chat.sel || {};
    return chatList().map((it) => `
      <div class="chat-user ${sel.kind === it.kind && sel.id === it.id ? "active" : ""}" onclick="NFI.chatPick('${it.kind}','${it.id || ""}','${esc(it.title)}')">
        <span class="avatar mini">${it.kind === "main" ? "♯" : esc(it.title.replace("تیم: ", "").charAt(0))}</span>
        <strong>${esc(it.title)}</strong>
      </div>`).join("");
  }

  function renderChat(c) {
    c.innerHTML = `
      <div class="chat-layout">
        <div class="chat-side">
          <div class="chat-tabs" style="padding:12px;font-weight:700;color:var(--text-mut)">گفتگوها</div>
          <div class="chat-users" id="chat-users"></div>
        </div>
        <div class="chat-main">
          <div class="chat-head" id="chat-head"><span>...</span><div class="chat-head-actions" id="chat-head-actions"></div></div>
          <div class="warn-box" id="warn-box"></div>
          <div class="chat-msgs" id="chat-msgs"><div class="empty-state"><p>در حال بارگذاری...</p></div></div>
          <div class="chat-input" id="chat-input-wrap"></div>
        </div>
      </div>`;
    const box = $("#chat-users");
    if (box) box.innerHTML = chatSideHtml();
    loadChatMsgs();
  }

  function chatPick(kind, id, title) {
    state.chat.sel = { kind, id: id || null, title };
    const box = $("#chat-users");
    if (box) box.innerHTML = chatSideHtml();
    loadChatMsgs();
    focusChatInput();
  }
  function focusChatInput() {
    setTimeout(() => { const inp = $("#chat-text"); if (inp) inp.focus(); }, 40);
  }
  function goChatTeam(id, name) {
    state.chat.sel = { kind: "team", id, title: name };
    switchView("chat");
  }

  async function loadChatMsgs() {
    const sel = state.chat.sel || { kind: "main" };
    const msgs = $("#chat-msgs"), head = $("#chat-head"), inputWrap = $("#chat-input-wrap"), acts = $("#chat-head-actions");
    if (!msgs || !head) return;
    let list = [], title = sel.title || "چت";
    try {
      const url = sel.kind === "team" ? "/api/chat/team/" + encodeURIComponent(sel.id) : "/api/chat/main";
      const r = await api(url);
      list = r.messages || [];
      if (r.team) title = "چت تیم: " + r.team;
    } catch (e) { if (e.status !== 401) toast(e.message, "error"); return; }
    head.innerHTML = `<span>${esc(title)}</span><div class="chat-head-actions">${acts ? acts.innerHTML : ""}</div>`;
    msgs.innerHTML = list.map((m) => `<div data-mid="${esc(m.id)}">${msgHTML(m)}</div>`).join("") || `<div class="empty-state"><p>هنوز پیامی نیست</p></div>`;
    msgs.scrollTop = msgs.scrollHeight;
    state.chatMaxAt = list.reduce((mx, m) => Math.max(mx, m.at || 0), 0);
    const activeEl = document.activeElement;
    const keepInput = activeEl && activeEl.id === "chat-text" && (activeEl.value || "").trim().length > 0;
    if (!keepInput) {
      inputWrap.innerHTML = `
        <input type="text" id="chat-text" placeholder="پیام خود را بنویسید..." autocomplete="off">
        ${canWarn() ? `<button type="button" class="btn btn-amber" id="warn-btn" title="ارسال اخطار">⚠</button>` : ""}
        <button type="button" class="btn btn-primary" id="chat-send">ارسال</button>`;
      const inp = $("#chat-text"), send = $("#chat-send");
      const doSend = () => sendChatMessage();
      send.addEventListener("click", doSend);
      inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); doSend(); } });
      if (canWarn()) $("#warn-btn").addEventListener("click", showWarnModal);
    }
    renderWarnings();
    startChatPoll();
  }

  async function sendChatMessage() {
    const inp = $("#chat-text");
    if (!inp) return;
    const text = inp.value.trim();
    if (!text) return;
    const sel = state.chat.sel || { kind: "main" };
    const url = sel.kind === "team" ? "/api/chat/team/" + encodeURIComponent(sel.id) : "/api/chat/main";
    try {
      await api(url, { method: "POST", body: JSON.stringify({ text }) });
      inp.value = "";
      loadChatMsgs();
    } catch (err) { toast(err.message, "error"); }
  }

  function startChatPoll() {
    chatPollGen++;
    chatPollTick(chatPollGen);
  }

  async function chatPollTick(gen) {
    if (gen !== chatPollGen || state.activeView !== "chat") return;
    const sel = state.chat.sel || { kind: "main" };
    const scope = sel.kind === "team" ? ("team:" + sel.id) : "main";
    let r = null;
    try {
      r = await api("/api/chat/poll?scope=" + encodeURIComponent(scope) + "&after=" + (state.chatMaxAt || 0));
    } catch (e) {
      if (e.status === 401) return;
    }
    if (gen !== chatPollGen) return;
    if (r && (r.messages || []).length) appendChatMsgs(r.messages);
    setTimeout(() => chatPollTick(gen), 200);
  }

  function appendChatMsgs(items) {
    const box = $("#chat-msgs");
    if (!box) return;
    state.chatMaxAt = Math.max(state.chatMaxAt || 0, ...(items || []).map((m) => m.at || 0));
    const seen = new Set(Array.from(box.querySelectorAll("[data-mid]")).map((n) => n.getAttribute("data-mid")));
    const fresh = (items || []).filter((m) => !seen.has(String(m.id)));
    if (!fresh.length) return;
    const empty = box.querySelector(".empty-state");
    if (empty) empty.remove();
    const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 140;
    box.insertAdjacentHTML("beforeend", fresh.map((m) => `<div data-mid="${esc(m.id)}">${msgHTML(m)}</div>`).join(""));
    if (nearBottom) box.scrollTop = box.scrollHeight;
  }

  function msgHTML(m) {
    const del = isAdmin() ? `<button class="btn btn-danger btn-sm msg-del" onclick="NFI.deleteMessage('${m.id}')">حذف</button>` : "";
    return `
      <div class="bubble ${m.from === state.me.username ? "mine" : ""}">
        <div class="bubble-meta">
          <strong>${esc(m.from_name || m.from)}</strong>
          <span class="muted">${fmtTime(m.at)}</span>
          ${del}
        </div>
        <div class="bubble-text">${esc(m.text)}</div>
      </div>`;
  }

  async function deleteMessage(id) {
    if (!confirm("این پیام حذف شود؟")) return;
    try {
      await api("/api/messages/" + id, { method: "DELETE", body: "{}" });
      toast("پیام حذف شد", "success");
      loadChatMsgs();
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Teams ----------------
  function teamCard(t) {
    const can = canManageTeams();
    const canChat = isApprover() || (t.members || []).some((m) => m.username === state.me.username);
    return `
    <div class="team-card">
      <div class="flex" style="justify-content:space-between;flex-wrap:wrap;gap:8px">
        <div class="flex" style="gap:10px">
          <span class="avatar">${esc(t.name.charAt(0))}</span>
          <div>
            <strong>${esc(t.name)}</strong>
            <div class="muted" style="font-size:12px">${t.members_count} عضو · ساخته‌شده توسط ${esc(t.created_by)}</div>
          </div>
        </div>
        ${canChat ? `<button class="btn btn-primary btn-sm" onclick="NFI.goChatTeam('${t.id}','${esc(t.name)}')">ورود به چت تیم</button>` : ""}
      </div>
      ${t.description ? `<div class="muted" style="font-size:13px;margin-top:8px">${esc(t.description)}</div>` : ""}
      <div class="team-members">
        ${(t.members || []).map((m) => `
          <span class="member-chip">
            <span class="avatar mini">${esc((m.name || m.username).charAt(0))}</span>
            ${esc(m.name || m.username)} <span class="muted" style="font-size:11px">(${ROLE_FA[m.role] || m.role})</span>
          </span>`).join("") || `<span class="muted">عضوی ندارد</span>`}
      </div>
      ${can ? `
      <div class="flex" style="margin-top:12px;flex-wrap:wrap;gap:6px">
        <button class="btn btn-sm" onclick="NFI.showTeamMembers('${t.id}','${esc(t.name)}')">مدیریت اعضا</button>
        <button class="btn btn-sm" onclick="NFI.editTeam('${t.id}','${esc(t.name)}','${esc(t.description || "")}')">ویرایش</button>
        <button class="btn btn-danger btn-sm" onclick="NFI.deleteTeam('${t.id}','${esc(t.name)}')">حذف تیم</button>
      </div>` : ""}
    </div>`;
  }

  function renderTeams(c) {
    const can = canManageTeams();
    c.innerHTML = `
      <div class="section-title">
        <h2>تیم‌ها</h2>
        ${can ? `<button class="btn btn-primary btn-sm" onclick="NFI.showAddTeam()">+ ساخت تیم</button>` : ""}
      </div>
      <div class="card">
        ${state.teams.length ? state.teams.map((t) => teamCard(t)).join("") : `<div class="empty-state"><p>تیمی ساخته نشده است</p></div>`}
      </div>`;
  }

  function teamForm(t) {
    t = t || {};
    return `
    <form onsubmit="NFI.saveTeam(event)">
      <div class="field"><label>نام تیم *</label><input type="text" id="t-name" required value="${esc(t.name || "")}"></div>
      <div class="field"><label>توضیحات</label><textarea id="t-desc">${esc(t.description || "")}</textarea></div>
      <div class="form-actions">
        <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
        <button type="submit" class="btn btn-primary">${t.id ? "ذخیره" : "ساخت"}</button>
      </div>
    </form>`;
  }
  const teamModal = (title, html) => openModal(title, html);
  function showAddTeam() { state.editingId = null; teamModal("ساخت تیم", teamForm()); }
  function editTeam(id, name, desc) { state.editingId = id; teamModal("ویرایش تیم «" + name + "»", teamForm({ id, name, description: desc })); }
  async function saveTeam(e) {
    e.preventDefault();
    const body = JSON.stringify({ name: $("#t-name").value.trim(), description: $("#t-desc").value.trim() });
    try {
      if (state.editingId) await api("/api/teams/" + state.editingId, { method: "PUT", body });
      else await api("/api/teams", { method: "POST", body });
      closeModal();
      toast("انجام شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function deleteTeam(id, name) {
    if (!confirm("تیم «" + name + "» برای همیشه حذف شود؟")) return;
    try {
      await api("/api/teams/" + id, { method: "DELETE", body: "{}" });
      toast("تیم حذف شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  function showTeamMembers(id, name) {
    const t = state.teams.find((x) => x.id === id);
    const current = (t ? t.members : []).map((m) => `
      <div class="flex" style="justify-content:space-between;padding:6px 0">
        <div class="flex" style="gap:8px"><span class="avatar mini">${esc((m.name || m.username).charAt(0))}</span>${esc(m.name || m.username)}</div>
        <button type="button" class="btn btn-danger btn-sm" onclick="NFI.removeTeamMember('${id}','${esc(m.username)}')">حذف</button>
      </div>`).join("");
    const avail = state.users.filter((u) => !(t || { members: [] }).members.some((m) => m.username === u.username));
    teamModal("مدیریت اعضای «" + name + "»", `
      <div class="muted" style="margin-bottom:6px">اعضای فعلی</div>
      ${current || `<div class="empty-state" style="padding:10px"><p>عضو ندارد</p></div>`}
      <div style="margin:12px 0;border-top:1px solid var(--border)"></div>
      <form onsubmit="NFI.addTeamMember(event,'${id}')">
        <div class="field"><label>افزودن کاربر</label>
          <select id="tm-user">
            ${avail.map((u) => `<option value="${esc(u.username)}">${esc(u.name || u.username)} (@${esc(u.username)})</option>`).join("") || `<option value="">کاربری برای افزودن نیست</option>`}
          </select>
        </div>
        <div class="form-actions"><button type="submit" class="btn btn-primary">افزودن به تیم</button></div>
      </form>`);
  }
  async function addTeamMember(e, id) {
    e.preventDefault();
    const username = $("#tm-user").value;
    if (!username) return;
    try {
      await api("/api/teams/" + id + "/members", { method: "POST", body: JSON.stringify({ username }) });
      toast("عضو اضافه شد", "success");
      await reload();
      const t = state.teams.find((x) => x.id === id);
      if (t) showTeamMembers(id, t.name);
    } catch (err) { toast(err.message, "error"); }
  }
  async function removeTeamMember(id, username) {
    if (!confirm("@ " + username + " از تیم حذف شود؟")) return;
    try {
      await api("/api/teams/" + id + "/members/" + encodeURIComponent(username), { method: "DELETE", body: "{}" });
      toast("عضو حذف شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- مدیریت ----------------
  function renderManage(c) {
    const tab = state.manageTab;
    c.innerHTML = `
      <div class="sub-tabs">
        <button class="sub-tab ${tab === "doc" ? "active" : ""}" onclick="NFI.manageTab('doc')">سند فاکتور فروش</button>
        <button class="sub-tab ${tab === "people" ? "active" : ""}" onclick="NFI.manageTab('people')">افراد تیم</button>
      </div>
      <div id="manage-body"></div>`;
    const body = $("#manage-body");
    if (tab === "doc") renderInvoiceDoc(body);
    else renderPeople(body);
  }
  function manageTab(t) { state.manageTab = t; renderCurrent(); }

  function renderInvoiceDoc(body) {
    const cur = state.settings.currency || "$";
    const defaultRange = () => {
      const t = new Date(); const f = new Date(); f.setDate(f.getDate() - 30);
      return { from: f.toISOString().slice(0, 10), to: t.toISOString().slice(0, 10) };
    };
    const rng = state.docRange || defaultRange();
    body.innerHTML = `
      <div class="card">
        <p class="muted" style="margin-bottom:12px;font-size:13px">گزارش فروش (سفارش‌ها) در بازه زمانی انتخابی</p>
        <div class="form-grid">
          <div class="field"><label>از تاریخ *</label><input type="date" id="doc-from" value="${esc(rng.from)}"></div>
          <div class="field"><label>تا تاریخ *</label><input type="date" id="doc-to" value="${esc(rng.to)}"></div>
          <div class="field" style="align-self:end"><button class="btn btn-primary btn-block" onclick="NFI.runDoc()">دریافت گزارش</button></div>
        </div>
      </div>
      <div id="doc-results">${state.docData ? docResultsHtml(state.docData, cur) : ""}</div>`;
  }

  function docResultsHtml(r, cur) {
    const s = r.summary || {};
    const card = (label, value) => `<div class="stat-card"><div class="stat-label">${label}</div><div class="stat-value">${value}</div></div>`;
    return `
      <div class="stats-grid" style="margin-top:14px">
        ${card("تعداد سفارش‌ها", s.count)}
        ${card("هزینه اصلی", fmtMoney(s.main_cost, cur))}
        ${card("هزینه ساخت", fmtMoney(s.build_cost, cur))}
        ${card("سود ناخالص", fmtMoney(s.gross_profit, cur))}
        ${card("سود خالص", fmtMoney(s.net_profit, cur))}
      </div>
      <div class="card" style="margin-top:14px">
        <div class="section-title" style="margin:0 0 10px"><h2>سفارش‌ها (${(r.items || []).length})</h2></div>
        ${(r.items || []).length ? `<div class="table-wrap"><table>
          <thead><tr><th>نام</th><th>نوع</th><th>هزینه اصلی</th><th>هزینه ساخت</th><th>سود ناخالص</th><th>سود خالص</th><th>تاریخ</th></tr></thead>
          <tbody>${(r.items || []).map((o) => `
            <tr>
              <td>${esc(o.name || o.title || "-")}</td>
              <td>${ORDER_TYPE_FA[o.type] || o.type || "سایر"}</td>
              <td>${fmtMoney(o.main_cost, cur)}</td>
              <td>${fmtMoney(o.build_cost, cur)}</td>
              <td>${fmtMoney(o.gross_profit, cur)}</td>
              <td>${fmtMoney(o.net_profit, cur)}</td>
              <td>${fmtTime(o.created_at)}</td>
            </tr>`).join("")}
          </tbody>
        </table></div>` : `<div class="empty-state"><p>در این بازه سفارشی ثبت نشده</p></div>`}
      </div>`;
  }

  async function runDoc() {
    const from = $("#doc-from").value, to = $("#doc-to").value;
    if (!from || !to) return toast("از و تا تاریخ را انتخاب کنید", "error");
    try {
      const r = await api("/api/invoice-doc?from=" + encodeURIComponent(from) + "&to=" + encodeURIComponent(to));
      state.docData = r;
      state.docRange = { from, to };
      renderCurrent();
    } catch (e) { toast(e.message, "error"); }
  }

  function renderPeople(body) {
    const can = canManagePeople();
    const kinds = [["all", "همه"], ["manager", "مدیر"], ["supervisor", "سرپرست"], ["teammate", "هم‌تیمی"], ["customer", "مشتری"], ["partner", "همکار"]];
    const q = (state.peopleFilter.q || "").toLowerCase();
    const list = state.people.filter((p) => {
      if (state.peopleFilter.kind !== "all" && p.kind !== state.peopleFilter.kind) return false;
      if (q && !((p.full_name || "").toLowerCase().includes(q) || (p.phone || "").includes(q) || (p.company || "").toLowerCase().includes(q))) return false;
      return true;
    });
    body.innerHTML = `
      <div class="card">
        <div class="filter-bar">
          <select id="pp-kind">
            ${kinds.map((k) => `<option value="${k[0]}"${state.peopleFilter.kind === k[0] ? " selected" : ""}>${k[1]}</option>`).join("")}
          </select>
          <input type="text" id="pp-q" placeholder="جستجو: نام، شرکت، شماره تماس..." value="${esc(state.peopleFilter.q)}">
          <button class="btn" onclick="NFI.applyPeopleFilter()">جستجو</button>
          ${can ? `<button class="btn btn-primary" onclick="NFI.showAddPerson()">+ ثبت فرد</button>` : ""}
        </div>
      </div>
      <div class="card">
        ${list.length ? `<div class="table-wrap"><table>
          <thead><tr><th>فرد</th><th>نوع</th><th>شماره تماس</th><th>تاریخ تولد</th><th>سن</th><th>سال تولد</th><th>شغل</th><th>حقوق</th><th>حضور</th><th>شرکت / تیم / فروشگاه</th><th>عملیات</th></tr></thead>
          <tbody>${list.map((p) => peopleRow(p)).join("")}</tbody>
        </table></div>` : `<div class="empty-state"><p>فردی مطابق فیلتر یافت نشد</p></div>`}
      </div>`;
    const sel = $("#pp-kind");
    const inp = $("#pp-q");
    if (sel) sel.addEventListener("change", () => { state.peopleFilter.kind = sel.value; renderCurrent(); });
    if (inp) inp.addEventListener("keydown", (e) => { if (e.key === "Enter") NFI.applyPeopleFilter(); });
  }
  function applyPeopleFilter() {
    const sel = $("#pp-kind"), q = $("#pp-q");
    state.peopleFilter.kind = sel ? sel.value : state.peopleFilter.kind;
    state.peopleFilter.q = q ? q.value : state.peopleFilter.q;
    renderCurrent();
  }

  function personThumb(p) {
    if (p.photo) return `<img class="person-thumb" src="${esc(p.photo)}" alt="">`;
    return `<span class="avatar mini">${esc((p.full_name || "?").charAt(0))}</span>`;
  }

  function peopleRow(p) {
    const cur = state.settings.currency || "$";
    const can = canManagePeople();
    return `
      <tr>
        <td><div class="flex" style="gap:8px">${personThumb(p)}<strong>${esc(p.full_name)}</strong></div></td>
        <td><span class="badge ${PERSON_KIND_BADGE[p.kind] || "user"}">${PERSON_KIND_FA[p.kind] || p.kind}</span></td>
        <td class="mono" dir="ltr">${esc(p.phone)}</td>
        <td>${p.birth_date ? `<span dir="ltr">${esc(p.birth_date)}</span>` : "—"}</td>
        <td>${p.age != null ? p.age + " سال" : "—"}</td>
        <td>${p.birth_year ? esc(p.birth_year) : "—"}</td>
        <td>${esc(p.job || "—")}</td>
        <td>${p.salary ? fmtMoney(p.salary, cur) : "—"}</td>
        <td>${p.presence ? `<span class="badge ${p.presence === "present" ? "green" : p.presence === "absent" ? "red" : "user"}">${PRESENCE_FA[p.presence] || p.presence}</span>` : "—"}</td>
        <td>${esc(p.company)}</td>
        <td>
          <div class="row-actions">
            <button class="btn btn-sm" onclick="NFI.viewPerson('${p.id}')">مشاهده پرونده</button>
            ${can ? `<button class="btn btn-sm" onclick="NFI.editPerson('${p.id}')">ویرایش</button>
            <button class="btn btn-danger btn-sm" onclick="NFI.deletePerson('${p.id}','${esc(p.full_name)}')">حذف</button>` : ""}
          </div>
        </td>
      </tr>`;
  }

  function personForm(p) {
    p = p || {};
    const kinds = Object.keys(PERSON_KIND_FA);
    return `
    <form onsubmit="NFI.savePerson(event)">
      <div class="form-grid">
        <div class="field"><label>نوع *</label><select id="pp-kind-f">
          ${kinds.map((k) => `<option value="${k}"${p.kind === k ? " selected" : ""}>${PERSON_KIND_FA[k]}</option>`).join("")}
        </select></div>
        <div class="field"><label>نام *</label><input type="text" id="pp-fname" required value="${esc(p.first_name || "")}"></div>
        <div class="field"><label>نام خانوادگی</label><input type="text" id="pp-lname" value="${esc(p.last_name || "")}"></div>
        <div class="field"><label>شماره تماس *</label><input type="text" id="pp-phone" required value="${esc(p.phone || "")}"></div>
        <div class="field"><label>تاریخ تولد</label><input type="date" id="pp-birth" value="${esc(p.birth_date || "")}" onchange="NFI.updatePpAge()"></div>
        <div class="field"><label>سن (خودکار)</label><div class="total-box" id="pp-age">${p.age != null ? p.age + " سال" : "—"}</div></div>
        <div class="field"><label>شغل</label><input type="text" id="pp-job" value="${esc(p.job || "")}"></div>
        <div class="field"><label>حقوق</label><input type="text" id="pp-salary" value="${esc(p.salary || "")}"></div>
        <div class="field"><label>وضعیت حضور</label><select id="pp-presence">
          <option value="">—</option>
          ${Object.keys(PRESENCE_FA).map((k) => `<option value="${k}"${p.presence === k ? " selected" : ""}>${PRESENCE_FA[k]}</option>`).join("")}
        </select></div>
        <div class="field full"><label>شرکت / تیم / فروشگاه *</label><input type="text" id="pp-company" required value="${esc(p.company || "")}"></div>
        <div class="field full"><label>عکس (اختیاری)</label>
          <input type="file" id="pp-photo" accept="image/*" onchange="NFI.ppPhotoChanged()">
          <div id="pp-photo-prev">${p.photo ? `<img class="person-thumb big" src="${esc(p.photo)}">` : ""}</div>
        </div>
        <div class="field full"><label>یادداشت</label><textarea id="pp-notes">${esc(p.notes || "")}</textarea></div>
      </div>
      <div class="form-actions">
        <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
        <button type="submit" class="btn btn-primary">${p.id ? "ذخیره تغییرات" : "ثبت فرد"}</button>
      </div>
    </form>`;
  }
  function ppPhotoChanged() {
    const f = $("#pp-photo");
    if (!f || !f.files || !f.files[0]) return;
    const file = f.files[0];
    if (file.size > 500 * 1024) return toast("حجم عکس نباید بیشتر از 500 کیلوبایت باشد", "error");
    const reader = new FileReader();
    reader.onload = () => {
      state.tempPhoto = reader.result;
      const prev = $("#pp-photo-prev");
      if (prev) prev.innerHTML = `<img class="person-thumb big" src="${esc(state.tempPhoto)}">`;
    };
    reader.readAsDataURL(file);
  }
  function updatePpAge() {
    const v = $("#pp-birth").value;
    const box = $("#pp-age");
    if (!box) return;
    if (!v) { box.textContent = "—"; return; }
    const bd = new Date(v + "T00:00:00");
    const now = new Date();
    let age = now.getFullYear() - bd.getFullYear();
    const m = now.getMonth() - bd.getMonth();
    if (m < 0 || (m === 0 && now.getDate() < bd.getDate())) age--;
    box.textContent = (age >= 0 && age <= 120) ? age + " سال" : "نامعتبر";
  }
  function showAddPerson() { state.editingId = null; state.tempPhoto = null; openModal("ثبت فرد", personForm()); }
  function editPerson(id) {
    const p = state.people.find((x) => x.id === id);
    if (!p) return;
    state.editingId = id;
    state.tempPhoto = null;
    openModal("ویرایش پرونده «" + p.full_name + "»", personForm(p));
  }
  async function savePerson(e) {
    e.preventDefault();
    const body = JSON.stringify({
      kind: $("#pp-kind-f").value,
      first_name: $("#pp-fname").value.trim(),
      last_name: $("#pp-lname").value.trim(),
      phone: $("#pp-phone").value.trim(),
      birth_date: $("#pp-birth").value,
      job: $("#pp-job").value.trim(),
      salary: $("#pp-salary").value.trim(),
      presence: $("#pp-presence").value,
      company: $("#pp-company").value.trim(),
      notes: $("#pp-notes").value.trim(),
      photo: state.tempPhoto || undefined,
    });
    try {
      if (state.editingId) await api("/api/people/" + state.editingId, { method: "PUT", body });
      else await api("/api/people", { method: "POST", body });
      closeModal();
      state.tempPhoto = null;
      toast("ثبت شد", "success");
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  async function deletePerson(id, name) {
    if (!confirm("پرونده «" + name + "» برای همیشه حذف شود؟")) return;
    try {
      await api("/api/people/" + id, { method: "DELETE", body: "{}" });
      toast("پرونده حذف شد", "success");
      if (state.personDetail === id) state.personDetail = null;
      await reload();
    } catch (err) { toast(err.message, "error"); }
  }
  function viewPerson(id) { state.personDetail = id; renderCurrent(); }
  function closePerson() { state.personDetail = null; renderCurrent(); }

  function renderPersonDetail(c, id) {
    const p = state.people.find((x) => x.id === id);
    if (!p) { state.personDetail = null; renderCurrent(); return; }
    const can = canManagePeople();
    const row = (label, value) => `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value">${value || "—"}</span></div>`;
    c.innerHTML = `
      <div class="flex" style="margin-bottom:14px;flex-wrap:wrap;gap:8px">
        <button class="btn btn-ghost btn-sm" onclick="NFI.closePerson()">← برگشت</button>
        <h2 style="font-size:18px">پرونده ${esc(p.full_name)}</h2>
        ${can ? `<div class="row-actions" style="margin-inline-start:auto">
          <button class="btn btn-sm" onclick="NFI.editPerson('${p.id}')">ویرایش</button>
          <button class="btn btn-danger btn-sm" onclick="NFI.deletePerson('${p.id}','${esc(p.full_name)}')">حذف</button>
        </div>` : ""}
      </div>
      <div class="profile-card">
        <div class="profile-photo-wrap">
          ${p.photo ? `<img class="profile-photo" src="${esc(p.photo)}" alt="">` : `<div class="profile-photo ph">${esc(p.full_name.charAt(0))}</div>`}
          <span class="badge ${PERSON_KIND_BADGE[p.kind] || "user"}">${PERSON_KIND_FA[p.kind] || p.kind}</span>
        </div>
        <div class="profile-info">
          ${row("نام", p.first_name)}
          ${row("نام خانوادگی", p.last_name)}
          ${row("شماره تماس", `<span class="mono" dir="ltr">${esc(p.phone)}</span>`)}
          ${row("تاریخ تولد", p.birth_date)}
          ${row("سن", p.age != null ? p.age + " سال" : "")}
          ${row("سال تولد", p.birth_year || "")}
          ${row("شغل", p.job)}
          ${row("حقوق", p.salary ? fmtMoney(p.salary, state.settings.currency || "$") : "")}
          ${row("وضعیت حضور", p.presence ? PRESENCE_FA[p.presence] || p.presence : "")}
          ${row("شرکت / تیم / فروشگاه", p.company)}
          ${row("یادداشت", p.notes)}
          ${row("ثبت توسط", p.created_by)}
          ${row("تاریخ ثبت", p.created_at ? fmtTime(p.created_at) : "")}
        </div>
      </div>`;
  }

  // ---------------- Warnings ----------------
  function renderWarnings() {
    const box = $("#warn-box");
    if (!box) return;
    const unseen = (state.warnings || []).filter((w) => !state.seenWarnings[w.id]);
    box.innerHTML = unseen.map((w) => `
      <div class="warn-item">
        <strong>⚠ اخطار</strong> — <span>${esc(w.from_name || w.from)}:</span> ${esc(w.text)}
        <button class="icon-btn btn-sm-x warn-x" onclick="NFI.hideWarning('${w.id}')">✕</button>
      </div>`).join("");
  }

  function hideWarning(id) {
    if (state.seenWarnings[id] === undefined) state.seenWarnings[id] = true;
    saveSeenWarnings();
    renderWarnings();
  }

  function showWarnModal() {
    openModal("ارسال اخطار", `
      <form onsubmit="NFI.submitWarning(event)">
        <div class="field"><label>متن اخطار *</label><textarea id="w-text" required></textarea></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
          <button type="submit" class="btn btn-amber">ارسال اخطار</button>
        </div>
      </form>`);
  }
  async function submitWarning(e) {
    e.preventDefault();
    try {
      await api("/api/warnings", { method: "POST", body: JSON.stringify({ text: $("#w-text").value.trim() }) });
      closeModal();
      toast("اخطار ارسال شد", "success");
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Alerts ----------------
  function refreshAlertsPanel() {
    const wrap = $("#alert-wrap");
    if (!wrap) return;
    const unseen = (state.alertsCache || []).filter((a) => state.seenAlerts[a.id] === false);
    if (!unseen.length) { wrap.style.display = "none"; return; }
    wrap.style.display = "block";
    $("#alert-list").innerHTML = unseen.map((a) => `
      <div class="alert-item" style="border-inline-start:4px solid ${esc(a.color || "#2ed9a4")}">
        <div class="alert-text">${esc(a.text)}</div>
        <div class="alert-meta">${esc(a.from_name || a.from)} · ${fmtTime(a.at)}</div>
        <button class="btn btn-sm btn-ghost" onclick="NFI.dismissAlert('${a.id}')">تایید</button>
      </div>`).join("");
  }

  function dismissAlert(id) {
    if (state.seenAlerts[id] === false) state.seenAlerts[id] = true;
    saveSeenAlerts();
    refreshAlertsPanel();
  }

  function sendAlert() {
    openModal("ارسال الرت به تیم", `
      <form onsubmit="NFI.submitAlert(event)">
        <div class="field"><label>متن الرت *</label><textarea id="al-text" required></textarea></div>
        <div class="field"><label>رنگ الرت</label><div class="color-row" id="color-row">
          ${ALERT_COLORS.map((c) => `<button type="button" class="color-dot" data-c="${c}" style="background:${c}"></button>`).join("")}
        </div><input type="hidden" id="al-color" value="#2ed9a4"></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick="NFI.closeModal()">انصراف</button>
          <button type="submit" class="btn btn-primary">ارسال</button>
        </div>
      </form>`);
    setTimeout(() => {
      const row = $("#color-row");
      if (row) row.querySelectorAll(".color-dot").forEach((b) => b.addEventListener("click", () => {
        row.querySelectorAll(".color-dot").forEach((d) => d.classList.remove("sel"));
        b.classList.add("sel");
        $("#al-color").value = b.dataset.c;
      }));
    }, 10);
  }
  async function submitAlert(e) {
    e.preventDefault();
    try {
      await api("/api/alerts", { method: "POST", body: JSON.stringify({ text: $("#al-text").value.trim(), color: $("#al-color").value }) });
      closeModal();
      toast("الرت ارسال شد", "success");
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- Settings ----------------
  function renderSettings(c) {
    const s = state.settings;
    c.innerHTML = `
      <div class="section-title"><h2>تنظیمات سامانه</h2></div>
      <div class="card">
        ${canEdit() ? `
        <form onsubmit="NFI.saveSettings(event)">
          <div class="form-grid">
            <div class="field"><label>نام سامانه</label><input type="text" id="s-name" value="${esc(s.site_name || "")}"></div>
            <div class="field"><label>واحد ارز</label><input type="text" id="s-currency" value="${esc(s.currency || "$")}" maxlength="10"></div>
            <div class="field full">
              <label><input type="checkbox" id="s-seo" class="check-inline" ${s.seo_noindex ? "checked" : ""}>
              خارج از ایندکس موتورهای جستجو (با فعال بودن، سایت بالا می‌آید اما در نتایج گوگل و سایر موتورها نمایش داده نمی‌شود)</label>
            </div>
          </div>
          <div class="form-actions"><button type="submit" class="btn btn-primary">ذخیره تنظیمات</button></div>
        </form>` : `
        <div class="field"><label>نام سامانه</label><input type="text" readonly value="${esc(s.site_name || "")}"></div>
        <div class="field"><label>واحد ارز</label><input type="text" readonly value="${esc(s.currency || "$")}"></div>`}
      </div>
      <div class="section-title"><h2>رمز عبور من</h2></div>
      <div class="card">
        <form onsubmit="NFI.changePassword(event)">
          <div class="form-grid">
            <div class="field"><label>رمز فعلی</label><input type="password" id="cp-current" required></div>
            <div class="field"><label>رمز جدید</label><input type="password" id="cp-new" required minlength="6"></div>
          </div>
          <div class="form-actions"><button type="submit" class="btn btn-primary">تغییر رمز</button></div>
        </form>
      </div>`;
  }

  async function saveSettings(e) {
    e.preventDefault();
    try {
      await api("/api/settings", { method: "PUT", body: JSON.stringify({
        site_name: $("#s-name").value.trim(), currency: $("#s-currency").value.trim(), seo_noindex: !!$("#s-seo").checked,
      }) });
      toast("تنظیمات ذخیره شد", "success");
      const r = await api("/api/settings");
      state.settings = r.settings || {};
    } catch (err) { toast(err.message, "error"); }
  }
  async function changePassword(e) {
    e.preventDefault();
    try {
      await api("/api/change-password", { method: "POST", body: JSON.stringify({ current: $("#cp-current").value, new: $("#cp-new").value }) });
      toast("رمز عبور تغییر کرد", "success");
      $("#cp-current").value = ""; $("#cp-new").value = "";
    } catch (err) { toast(err.message, "error"); }
  }

  // ---------------- exposed API ----------------
  window.NFI = {
    go: (v) => switchView(v),
    back: backToList,
    openDetail, addMedia: showAddMedia, editMedia, saveMedia, approveMedia, deleteMedia, addVersion, deleteVersion,
    showAddProject, editProject, saveProject, deleteProject,
    showAddOrder, editOrder, saveOrder, deleteOrder,
    showAddInvoice, editInvoice, saveInvoice, decideInvoice, deleteInvoice,
    showAddUser, saveUser, editUser, saveUserEdit, resetUserPw, toggleBan, deleteUser,
    chatPick, goChatTeam, deleteMessage,
    showAddTeam, editTeam, saveTeam, deleteTeam, showTeamMembers, addTeamMember, removeTeamMember,
    showAddPerson, editPerson, savePerson, deletePerson, viewPerson, closePerson, ppPhotoChanged, updatePpAge,
    applyPeopleFilter, manageTab, runDoc,
    showWarnModal, submitWarning, hideWarning,
    sendAlert, submitAlert, dismissAlert, closeModal,
    saveSettings, changePassword,
    toggleNotifDrop, markNotifRead: () => markNotifRead(true), toggleTheme,
  };

  document.addEventListener("DOMContentLoaded", boot);
})();