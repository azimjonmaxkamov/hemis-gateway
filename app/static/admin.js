/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Azimjon Makhkamov */
/* HEMIS Gateway — boshqaruv paneli (vanilla JS SPA) */
"use strict";
const { fmt, esc } = window.Charts;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const S = { me: null, meta: null, endpoints: null, clientsCache: null };
const ACT = {};   // data-act -> handler(el, ev)
const CHG = {};   // data-chg -> handler(el, ev)

/* ------------------------------------------------ yordamchilar */
async function api(method, url, body, isForm) {
  const opt = { method, credentials: "same-origin", headers: { "X-Requested-With": "hg-admin" } };
  if (body !== undefined) {
    if (isForm) opt.body = body;
    else { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  }
  const r = await fetch(url, opt);
  let data = null;
  try { data = await r.json(); } catch (_) { /* */ }
  if (r.status === 401 && !url.includes("/auth/login")) { S.me = null; renderLogin(); throw new Error("Sessiya tugadi"); }
  if (!r.ok) {
    let msg = data && (data.detail || data.error) || `Xato ${r.status}`;
    if (Array.isArray(msg)) msg = msg.map((d) => (d.loc || []).slice(1).join(".") + ": " + d.msg).join("; ");
    throw new Error(msg);
  }
  return data;
}
function toast(msg, err) {
  const d = document.createElement("div"); d.textContent = msg; if (err) d.className = "err";
  $("#toast").appendChild(d); setTimeout(() => d.remove(), err ? 6000 : 3000);
}
async function run(fn) { try { return await fn(); } catch (e) { toast(e.message, true); } }
const dt = (s) => (s ? new Date(s).toLocaleString("uz-UZ", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—");
const ago = (s) => {
  if (!s) return "hech qachon";
  const d = (Date.now() - new Date(s)) / 1000;
  if (d < 60) return "hozirgina"; if (d < 3600) return Math.floor(d / 60) + " daq. oldin";
  if (d < 86400) return Math.floor(d / 3600) + " soat oldin"; return Math.floor(d / 86400) + " kun oldin";
};
const bytes = (b) => (b > 1e9 ? (b / 1e9).toFixed(1) + " GB" : b > 1e6 ? (b / 1e6).toFixed(1) + " MB" : b > 1e3 ? (b / 1e3).toFixed(0) + " KB" : (b || 0) + " B");
const statusPill = (s) => `<span class="pill ${s < 300 ? "good" : s < 400 ? "plain" : s === 429 ? "warn" : s < 500 ? "serious" : "bad"}">${s}</span>`;
const riskPill = (r) => `<span class="pill ${r === "high" ? "bad" : r === "medium" ? "warn" : "good"}">${{ high: "yuqori xavf", medium: "o'rta", low: "past xavf" }[r] || r}</span>`;
const authLabel = (a) => ({ admin: "Admin token", passthrough: "Mijoz tokeni", public: "Ochiq", fast: "Fast API" }[a] || a);
const can = (...roles) => S.me && roles.includes(S.me.role);
const DENY = {
  no_key: "Kalit yo'q", invalid_key: "Noto'g'ri kalit", client_disabled: "Mijoz o'chirilgan", key_expired: "Kalit muddati o'tgan",
  ip_not_allowed: "IP ruxsatsiz", origin_not_allowed: "Domen ruxsatsiz", rate_limited: "Daqiqalik limit", rate_limited_second: "Soniyalik limit", ip_blocked: "IP bloklangan", client_suspended: "Mijoz to'xtatilgan", upstream_non_json: "HEMIS noto'g'ri format", quota_exceeded: "Kunlik kvota",
  unknown_endpoint: "Noma'lum endpoint", endpoint_disabled: "Endpoint o'chiq", endpoint_removed: "Endpoint hujjatdan olib tashlangan", locked_param_missing: "Qulflangan filtr yo'qolgan", endpoint_not_allowed: "Endpointga ruxsat yo'q",
  unknown_param: "Noma'lum filtr", param_not_allowed: "Filtrga ruxsat yo'q", duplicate_param: "Takroriy filtr",
  locked_value: "Qulflangan qiymat", locked_required: "Majburiy filtr yo'q", scope_violation: "Doiradan tashqari",
  scope_required: "Doira filtri yo'q", scope_unenforceable: "Doira bilan cheklab bo'lmaydi", bad_value: "Noto'g'ri qiymat",
  bad_path: "Noto'g'ri yo'l", too_many_bad_keys: "Brute-force bloki", upstream_busy: "HEMIS band", upstream_timeout: "HEMIS timeout",
  upstream_error: "HEMIS aloqa xatosi", upstream_auth: "HEMIS token xatosi", no_upstream_token: "Token sozlanmagan",
};

function modal(html, wide) {
  closeModal();
  const bg = document.createElement("div"); bg.className = "modal-bg"; bg.id = "modal";
  bg.innerHTML = `<div class="modal ${wide ? "wide" : ""}">${html}</div>`;
  bg.addEventListener("mousedown", (e) => { if (e.target === bg) closeModal(); });
  document.body.appendChild(bg);
  const f = $("input,select,textarea", bg); if (f) f.focus();
  return bg;
}
function closeModal() { const m = $("#modal"); if (m) m.remove(); }
ACT.close = closeModal;
ACT.copy = (el) => { navigator.clipboard.writeText(el.dataset.text || $(el.dataset.target).textContent).then(() => toast("Nusxa olindi")); };

document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (el && ACT[el.dataset.act]) { e.preventDefault(); ACT[el.dataset.act](el, e); }
  if (e.target.closest(".nav a")) $(".side")?.classList.remove("open");
});
document.addEventListener("change", (e) => { const el = e.target.closest("[data-chg]"); if (el && CHG[el.dataset.chg]) CHG[el.dataset.chg](el, e); });
document.addEventListener("input", (e) => { const el = e.target.closest("[data-inp]"); if (el && CHG[el.dataset.inp]) CHG[el.dataset.inp](el, e); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
document.addEventListener("submit", (e) => { const f = e.target.closest("form[data-submit]"); if (f) { e.preventDefault(); ACT[f.dataset.submit]?.(f, e); } });
ACT.menu = () => $(".side").classList.toggle("open");

/* ------------------------------------------------ ikonlar */
const I = {
  monitor: '<path d="M3 12h4l3-8 4 16 3-8h4"/>', stats: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  clients: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9h10M7 13h6"/>', key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3"/>',
  endpoints: '<path d="M4 6h16M4 12h16M4 18h10"/>', logs: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  audit: '<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/>', settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 01-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 010-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 014 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 010 4h-.1a1.7 1.7 0 00-1.5 1z"/>',
  shield: '<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M9 12l2 2 4-4"/>',
  admins: '<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6 7-6s7 2 7 6M17 11l2 2 4-4"/>', user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
};
const icon = (n) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${I[n]}</svg>`;

/* ------------------------------------------------ branding */
S.brand = { product: "HEMIS API Gateway", version: "", author: "Azimjon Makhkamov", license: "Apache-2.0", org_name: "", org_short: "", has_logo: false };
async function loadBrand() { try { S.brand = await fetch("/api/public/branding").then((r) => r.json()); } catch (_) { /* */ } }
const brandLogo = () => S.brand.has_logo ? `<img class="logo" src="/branding/logo" alt="" style="object-fit:contain;background:#fff">` : `<div class="logo">HG</div>`;
const footerHTML = () => `<div class="foot">${esc(S.brand.product)}${S.brand.version ? " v" + esc(S.brand.version) : ""} · © 2026 ${S.brand.url ? `<a href="${esc(S.brand.url)}" target="_blank" rel="noopener">${esc(S.brand.author)}</a>` : esc(S.brand.author)} · ${esc(S.brand.license)}</div>`;

/* ------------------------------------------------ login */
function renderLogin(otp) {
  $("#root").innerHTML = `<div class="login-wrap"><form class="card login" data-submit="login">
    <div class="brand">${brandLogo()}<div>${esc(S.brand.org_short || "HEMIS")} API Gateway<small>${esc(S.brand.org_name || "Boshqaruv paneli")}</small></div></div>
    <label class="f"><span>Login</span><input name="username" autocomplete="username" required></label>
    <label class="f"><span>Parol</span><input name="password" type="password" autocomplete="current-password" required></label>
    <label class="f" id="otpf" style="display:${otp ? "block" : "none"}"><span>2FA kod (Google Authenticator)</span><input name="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label>
    <div id="capf" style="display:none"><label class="f"><span>Rasmdagi belgilar</span><div class="row"><img id="capimg" alt="captcha" style="border-radius:6px;border:1px solid var(--border)"><button type="button" class="sm" data-act="capnew" title="Yangilash">↻</button></div><input name="captcha" autocomplete="off" maxlength="8" style="margin-top:6px"></label><input type="hidden" name="captcha_id"></div>
    <button class="primary" style="width:100%;justify-content:center">Kirish</button>
    <p class="muted small" style="margin:14px 0 0">Kirishlar va barcha amallar audit jurnaliga yoziladi.</p>${footerHTML()}</form></div>`;
}
async function loadCaptcha() {
  const r = await fetch("/api/captcha").then((x) => x.json());
  $("#capf").style.display = "block"; $("#capimg").src = r.image; $("[name=captcha_id]").value = r.captcha_id;
  const i = $("[name=captcha]"); i.value = ""; i.focus();
}
ACT.capnew = () => run(loadCaptcha);
ACT.login = (f) => run(async () => {
  const fd = Object.fromEntries(new FormData(f));
  const resp = await fetch("/api/admin/auth/login", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-Requested-With": "hg-admin" }, body: JSON.stringify(fd) });
  const r = await resp.json().catch(() => ({}));
  if (resp.status === 428) { await loadCaptcha(); throw new Error(r.detail); }
  if (!resp.ok) { if ($("#capf").style.display === "block") await loadCaptcha(); throw new Error(r.detail || "Xato " + resp.status); }
  if (r.otp_required) { $("#otpf").style.display = "block"; $("[name=otp]").focus(); toast("2FA kodni kiriting"); return; }
  S.me = r.admin; boot();
});

/* ------------------------------------------------ layout + router */
const NAV = [
  ["", "monitor", "Nazorat"], ["stats", "stats", "Statistika"],
  "Boshqaruv", ["clients", "clients", "Mijozlar"], ["endpoints", "endpoints", "Endpointlar"],
  "Jurnal", ["logs", "logs", "So'rovlar jurnali"], ["audit", "audit", "Admin amallari"],
  "Tizim", ["security", "shield", "Xavfsizlik"], ["settings", "settings", "Sozlamalar", ["superadmin"]], ["admins", "admins", "Adminlar", ["superadmin"]], ["profile", "user", "Profil"],
];
function layout() {
  $("#root").innerHTML = `<div class="app"><aside class="side">
    <div class="brand">${brandLogo()}<div>${esc(S.brand.org_short || "HEMIS")} Gateway<small>${esc(location.host)}</small></div></div>
    <nav class="nav">${NAV.map((n) => typeof n === "string" ? `<div class="sec">${n}</div>` : (n[3] && !can(...n[3])) ? "" : `<a href="#/${n[0]}" data-r="${n[0]}">${icon(n[1])}${n[2]}</a>`).join("")}</nav>
    <div class="me"><b>${esc(S.me.full_name || S.me.username)}</b><br><span class="muted">${esc(S.me.role)}</span> · <a href="#" data-act="logout">Chiqish</a></div>
    ${footerHTML()}
  </aside><main class="main" id="view"></main></div>`;
}
ACT.logout = () => run(async () => { await api("POST", "/api/admin/auth/logout"); S.me = null; renderLogin(); });

const ROUTES = {};
function route() {
  if (!S.me) return;
  const parts = location.hash.replace(/^#\/?/, "").split("?")[0].split("/");
  const name = parts[0] || "";
  $$(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.r === name));
  const v = $("#view"); v.innerHTML = '<div class="empty">Yuklanmoqda…</div>';
  window.Charts.hideTip();
  (ROUTES[name] || ROUTES[""])(v, parts.slice(1)).catch((e) => { v.innerHTML = `<div class="alert bad">${esc(e.message)}</div>`; });
}
window.addEventListener("hashchange", route);
let rsz; window.addEventListener("resize", () => { clearTimeout(rsz); rsz = setTimeout(() => window.onResize && window.onResize(), 150); });

function head(title, sub, right = "") {
  return `<div class="topbar"><div class="row" style="align-items:flex-start;gap:10px"><button class="menu-btn sm" data-act="menu" aria-label="Menyu">☰</button><div><h1>${title}</h1>${sub ? `<p class="sub">${sub}</p>` : ""}</div></div><div class="row">${right}</div></div>`;
}

async function loadMeta() { if (!S.meta) S.meta = await api("GET", "/api/admin/meta"); return S.meta; }
async function loadEndpoints(force) { if (!S.endpoints || force) S.endpoints = await api("GET", "/api/admin/endpoints"); return S.endpoints; }

/* ================================================= NAZORAT (monitoring) */
let monHours = 24, monTimer = null;
ROUTES[""] = async (v) => {
  clearInterval(monTimer);
  const draw = async () => {
    const d = await api("GET", "/api/admin/monitor/summary?hours=" + monHours);
    if (!$("#mon")) return;
    const okPct = d.total ? ((d.ok / d.total) * 100).toFixed(1) : "—";
    const cachePct = d.total ? ((d.cache_hits / d.total) * 100).toFixed(0) : 0;
    const steps = [
      [!!d.system.hemis_base && d.system.hemis_base !== "", "HEMIS manzili va admin tokenini kiriting", "#/settings"],
      [!!d.system.hemis_token, "HEMIS admin tokeni kiritilgan", "#/settings"],
      [!!S.brand.org_name, "OTM ma'lumotlari to'ldirilgan", "#/settings"],
      [d.system.endpoints > 0, "«Saqlash va sinxronlash» — HEMIS API hujjati (endpointlar) yuklangan", "#/settings"],
      [!!S.me.totp_enabled, "Admin parolini almashtiring va 2FA ni yoqing", "#/profile"],
      [d.system.clients > 0, "Birinchi mijoz (tashqi tizim) va uning ruxsatlarini yarating", "#/clients"],
    ];
    const setupDone = steps.every((x) => x[0]);
    $("#mon").innerHTML = `
      ${!setupDone ? `<div class="card" style="margin-bottom:14px"><h2>Boshlash — tizimni sozlash</h2>${steps.map(([ok, t, h]) => `<div class="row" style="margin:6px 0"><span class="pill ${ok ? "good" : "warn"}">${ok ? "bajarildi" : "kutilmoqda"}</span><a href="${h}">${esc(t)}</a></div>`).join("")}</div>` : ""}
      ${!d.system.hemis_token ? `<div class="alert bad">HEMIS admin tokeni sozlanmagan — Backend API so'rovlari ishlamaydi. <a href="#/settings">Sozlamalar</a></div>` : ""}
      <div class="grid g6">
        ${tile("Jami so'rovlar", fmt(d.total), `${monHours} soat ichida`)}
        ${tile("Muvaffaqiyatli", okPct + (d.total ? "%" : ""), fmt(d.ok) + " ta")}
        ${tile("Rad etilgan", fmt(d.denied), "401 / 403 / 429")}
        ${tile("Server xatolari", fmt(d.errors), "5xx (HEMIS / gateway)")}
        ${tile("O'rtacha javob", fmt(d.avg_latency_ms) + " ms", "kesh: " + cachePct + "%")}
        ${tile("Faol mijozlar", fmt(d.active_clients), "jami: " + d.system.clients + " · " + bytes(d.bytes))}
      </div>
      <div class="card mt"><h2>So'rovlar dinamikasi</h2><div id="ch-series"></div></div>
      <div class="grid g2 mt">
        <div class="card"><h2>Eng faol mijozlar</h2>${d.top_clients.length ? `<div class="table-wrap"><table><tr><th>Mijoz</th><th class="num">So'rov</th><th class="num">Rad/xato</th></tr>${d.top_clients.map((c) => `<tr class="click" data-act="go" data-href="#/clients/${c.client_id}"><td>${esc(c.name)}</td><td class="num">${fmt(c.count)}</td><td class="num">${c.denied ? `<span class="pill serious">${fmt(c.denied)}</span>` : "0"}</td></tr>`).join("")}</table></div>` : '<div class="empty">So\'rovlar yo\'q</div>'}</div>
        <div class="card"><h2>Rad etish sabablari</h2><div id="ch-reasons"></div></div>
        <div class="card"><h2>Eng ko'p chaqirilgan endpointlar</h2><div class="table-wrap"><table><tr><th>Yo'l</th><th class="num">So'rov</th><th class="num">O'rt. ms</th></tr>${d.top_paths.map((p) => `<tr><td class="mono">${esc(p.path)}</td><td class="num">${fmt(p.count)}</td><td class="num">${fmt(p.avg_ms)}</td></tr>`).join("") || '<tr><td colspan=3 class="empty">—</td></tr>'}</table></div></div>
        <div class="card"><h2>Shubhali IP manzillar</h2><p class="muted small" style="margin-top:-6px">Eng ko'p rad etilgan so'rov yuborganlar</p>${d.suspicious_ips.length ? `<table>${d.suspicious_ips.map((x) => `<tr><td class="mono"><a href="#/logs?ip=${encodeURIComponent(x.ip)}">${esc(x.ip)}</a></td><td class="num"><span class="pill serious">${fmt(x.count)}</span></td><td class="num">${can("superadmin", "admin") ? `<button class="sm danger" data-act="ipblock" data-ip="${esc(x.ip)}">Bloklash</button>` : ""}</td></tr>`).join("")}</table>` : '<div class="empty">Shubhali faollik yo\'q</div>'}
          <h3 class="mt">Tizim holati</h3><div class="chips"><span class="pill ${d.system.kv ? "good" : "bad"}">Redis/kesh</span><span class="pill ${d.system.hemis_token ? "good" : "bad"}">HEMIS token</span><span class="pill plain">${d.system.endpoints} endpoint</span></div>
          <div class="muted small mt mono">${esc(d.system.hemis_base)}</div></div>
      </div>`;
    const lab = (t) => { const x = new Date(t); return d.bucket === 3600 ? x.getHours().toString().padStart(2, "0") + ":00" : x.getDate() + "." + (x.getMonth() + 1); };
    const rows = d.series.map((s) => ({ label: lab(s.t), tipLabel: new Date(s.t).toLocaleString("uz-UZ", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }), ok: s.ok, denied: s.denied, error: s.error }));
    const css = getComputedStyle(document.documentElement);
    const drawS = () => window.Charts.stackedColumns($("#ch-series"), rows, [
      { key: "ok", label: "Muvaffaqiyatli", color: css.getPropertyValue("--good").trim() },
      { key: "denied", label: "Rad etilgan", color: css.getPropertyValue("--serious").trim() },
      { key: "error", label: "Xato (5xx)", color: css.getPropertyValue("--critical").trim() }], { label: "So'rovlar soni vaqt bo'yicha" });
    drawS(); window.onResize = drawS;
    window.Charts.hbars($("#ch-reasons"), d.deny_reasons.map((r) => ({ name: DENY[r.reason] || r.reason, value: r.count, sub: r.reason })), { color: "var(--serious)" });
  };
  v.innerHTML = head("Nazorat", "Gateway orqali o'tayotgan so'rovlar, rad etishlar va tizim holati",
    `<div class="seg">${[[1, "1 soat"], [24, "24 soat"], [168, "7 kun"], [720, "30 kun"]].map(([h, l]) => `<button class="${h === monHours ? "on" : ""}" data-act="monh" data-h="${h}">${l}</button>`).join("")}</div>`) + '<div id="mon"><div class="empty">Yuklanmoqda…</div></div>';
  await draw();
  monTimer = setInterval(() => { if (location.hash.replace(/^#\/?/, "") === "" && !document.hidden) draw().catch(() => {}); else clearInterval(monTimer); }, 30000);
};
ACT.monh = (el) => { monHours = +el.dataset.h; route(); };
ACT.go = (el) => { location.hash = el.dataset.href; };
const tile = (l, v, h) => `<div class="card tile"><div class="label">${l}</div><div class="value">${v}</div><div class="hint">${h || ""}</div></div>`;

/* ================================================= STATISTIKA */
const GB_LABELS = { education_form: "Ta'lim shakli", education_type: "Ta'lim turi", payment_form: "To'lov shakli", level: "Kurs", gender: "Jinsi", department: "Fakultet", employee_type: "Xodim turi", position: "Lavozim" };
const statState = { students: "education_form", employees: "employee_type", debtType: "1", debtGb: "department", attFrom: "", attTo: "" };

function unwrap(res) {
  // HEMIS ba'zan {success, data: {code, data: {...}}} ko'rinishida ichma-ich qaytaradi
  let d = res && (res.data ?? res.result ?? res);
  for (let i = 0; i < 3 && d && typeof d === "object" && !Array.isArray(d) && "data" in d && ("success" in d || "code" in d || "message" in d); i++) d = d.data;
  return d;
}
function deepSum(v) {
  if (typeof v === "number") return v;
  if (v && typeof v === "object") return Object.values(v).reduce((a, x) => a + deepSum(x), 0);
  return 0;
}
function itemsFrom(res) {
  // HEMIS javobidan {name,value} ro'yxatini topishga harakat qiladi
  const d = unwrap(res);
  const arr = Array.isArray(d) ? d : (d && (d.items || d.list || d.by_department || d.data));
  if (Array.isArray(arr) && arr.length && typeof arr[0] === "object") {
    const x0 = arr[0];
    const vk = ["debtor_count", "debtor_students", "total_absent_records", "count", "total", "students", "value"].find((k) => k in x0);
    const name = (x) => x.name ?? x.department_name ?? x.title ?? x.label ?? x.department?.name ?? x.group?.name
      ?? ([x.education_type_name, x.education_form_name].filter(Boolean).join(" · ") || x.code);
    if (vk) return arr.map((x) => ({ name: typeof name(x) === "object" ? name(x)?.name : String(name(x) ?? "—"), value: +x[vk] || 0,
      sub: x.pairs ? Object.entries(x.pairs).map(([k, v]) => `${k}: ${v}`).join(", ") : (x.percent != null ? x.percent + "%" : "") })).sort((a, b) => b.value - a.value);
  }
  return null;
}
function objNumbers(o) {
  if (!o || typeof o !== "object" || Array.isArray(o)) return null;
  const e = Object.entries(o).filter(([k, v]) => k && (typeof v === "number" || (v && typeof v === "object" && deepSum(v) >= 0 && Object.keys(v).length)));
  if (!e.length || e.every(([, v]) => deepSum(v) === 0 && typeof v !== "number")) return null;
  return e.map(([k, v]) => ({ name: (v && v.name) || k, value: typeof v === "number" ? v : ("count" in v ? +v.count : deepSum(v)) }))
    .filter((x) => !["total", "code"].includes(x.name)).sort((a, b) => b.value - a.value);
}
const KEY_L = { accommodation: "Yashash joyi", payment: "To'lov shakli", citizenship: "Fuqarolik", education_type: "Ta'lim turi", region: "Viloyat", age: "Yosh", level: "Kurs", education_form: "Ta'lim shakli", morning_shift: "1-smena", afternoon_shift: "2-smena", unknown_shift: "Noma'lum smena" };
function generic(el, res) {
  const it = itemsFrom(res);
  if (it) return window.Charts.hbars(el, it, { limit: 15 });
  const d = unwrap(res);
  if (d && typeof d === "object" && !Array.isArray(d)) {
    const vals = Object.values(d);
    const nested = vals.length && vals.every((v) => v && typeof v === "object" && !Array.isArray(v) && Object.values(v).some((x) => x && typeof x === "object"));
    if (nested) {   // masalan public/stat-student: har bir bo'lim alohida grafik
      const subs = Object.entries(d).map(([k, v]) => [k, objNumbers(v)]).filter(([, x]) => x && x.length > 1);
      if (subs.length) {
        el.innerHTML = `<div class="grid g2">${subs.map(([k], i) => `<div><h3>${esc(KEY_L[k] || k)}</h3><div id="gsub${i}"></div></div>`).join("")}</div>`;
        subs.forEach(([, x], i) => window.Charts.hbars($("#gsub" + i, el), x.map((y) => ({ ...y, name: KEY_L[y.name] || y.name })), { limit: 8 }));
        return;
      }
    }
    const on = objNumbers(d);
    if (on && on.length) return window.Charts.hbars(el, on.map((y) => ({ ...y, name: KEY_L[y.name] || y.name })), { limit: 15 });
  }
  el.innerHTML = `<pre class="json">${esc(JSON.stringify(res, null, 2)).slice(0, 20000)}</pre>`;
}
async function loadReport(name, params, target, render) {
  const el = $(target); if (!el) return;
  el.innerHTML = '<div class="empty">Yuklanmoqda…</div>';
  try {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
    const r = await api("GET", `/api/admin/stats/${name}${q ? "?" + q : ""}`);
    (render || generic)(el, r.result, r);
  } catch (e) { el.innerHTML = `<div class="alert bad">${esc(e.message)}</div>`; }
}
ROUTES.stats = async (v) => {
  window.onResize = null;
  const seg = (key, opts, act) => `<div class="seg">${opts.map((o) => `<button class="${statState[key] === o ? "on" : ""}" data-act="${act}" data-v="${o}">${GB_LABELS[o] || o}</button>`).join("")}</div>`;
  v.innerHTML = head("Statistika", "HEMIS ma'lumotlari asosida OTM ko'rsatkichlari (keshlanadi, 5–30 daqiqa)", `<button data-act="statref">Yangilash</button>`) + `
    <div class="grid g4" id="st-tiles"></div>
    <div class="grid g2 mt">
      <div class="card"><div class="row"><h2 style="margin:0">Talabalar</h2><span class="spacer"></span><span class="muted small" id="st-stotal"></span></div><div class="row mt">${seg("students", ["education_form", "education_type", "payment_form", "level", "gender", "department"], "sgb")}</div><div id="st-students" class="mt"></div></div>
      <div class="card"><div class="row"><h2 style="margin:0">Xodimlar</h2><span class="spacer"></span><span class="muted small" id="st-etotal"></span></div><div class="row mt">${seg("employees", ["employee_type", "department", "position", "gender"], "egb")}</div><div id="st-employees" class="mt"></div></div>
      <div class="card"><h2>Qarzdor talabalar — fakultetlar kesimida</h2><div id="st-debtors"></div></div>
      <div class="card"><h2>${statState.debtType === "1" ? "Akademik qarzdorlik" : "Dars qoldirish (10+ soat)"}</h2><div class="row">${seg("debtType", ["1", "2"], "dtype").replace(">1<", ">Akademik<").replace(">2<", ">Dars qoldirish<")}</div><div id="st-debt" class="mt"></div></div>
      <div class="card span2"><div class="row"><h2 style="margin:0">Davomat — fakultetlar bo'yicha</h2><span class="spacer"></span><input type="date" id="att-from" value="${statState.attFrom}"><input type="date" id="att-to" value="${statState.attTo}"><button class="sm" data-act="attgo">Ko'rsatish</button></div><div id="st-att" class="mt"></div></div>
      <div class="card"><h2>Bugungi dars qoldirish</h2><div id="st-daily"></div></div>
      <div class="card"><h2>Smenalar bo'yicha talabalar</h2><div id="st-shift"></div></div>
      <div class="card span2"><h2>Ochiq statistika (Public API)</h2><div id="st-public"></div></div>
    </div>`;
  loadAllStats(false);
};
function loadAllStats(refresh) {
  const R = refresh ? { refresh: "1" } : {};
  loadReport("students", { group_by: statState.students, ...R }, "#st-students", (el, res) => {
    const it = itemsFrom(res) || []; window.Charts.hbars(el, it, { limit: 14 });
    const t = res?.data?.total; $("#st-stotal").textContent = t ? "Jami: " + fmt(t) : "";
    $("#st-tiles").dataset.students = t || "";
    tiles();
  });
  loadReport("employees", { group_by: statState.employees, ...R }, "#st-employees", (el, res) => {
    window.Charts.hbars(el, itemsFrom(res) || [], { limit: 14 });
    const t = res?.data?.total; $("#st-etotal").textContent = t ? "Jami: " + fmt(t) : ""; $("#st-tiles").dataset.employees = t || ""; tiles();
  });
  loadReport("debtors", R, "#st-debtors", (el, res) => {
    const d = res?.result || res?.data || {};
    $("#st-tiles").dataset.debt = d.debtor_students ?? ""; $("#st-tiles").dataset.debtp = d.debtor_percentage ?? ""; tiles();
    const it = (d.by_department || []).map((x) => ({ name: x.department_name, value: x.debtor_students, sub: `${fmt(x.total_students)} talabadan, ${x.debtor_percentage}%` })).sort((a, b) => b.value - a.value);
    it.length ? window.Charts.hbars(el, it, { color: "var(--serious)", unit: "Qarzdorlar" }) : generic(el, res);
  });
  loadReport("debt_stats", { type: statState.debtType, group_by: statState.debtGb, ...R }, "#st-debt");
  loadReport("attendance", { group_by: "department", date_from: statState.attFrom, date_to: statState.attTo, ...R }, "#st-att", (el, res) => {
    const blocks = Array.isArray(res?.data) ? res.data : [res?.data];
    const items = blocks.flatMap((b) => (b && b.items) || []);
    if (!items.length) return generic(el, res);
    el.innerHTML = `<div class="table-wrap"><table><tr><th>Fakultet</th><th>Sana</th><th class="num">Talaba</th><th class="num">Dars</th><th class="num">Sababli</th><th class="num">Sababsiz</th><th class="num">Jami %</th></tr>${items.map((x) => `<tr><td>${esc(x.department?.name || x.group?.name || x.university?.name || "—")}</td><td>${esc(x.date || "")}</td><td class="num">${fmt(x.students)}</td><td class="num">${fmt(x.lessons)}</td><td class="num">${fmt(x.absent_on)}</td><td class="num">${fmt(x.absent_off)}</td><td class="num"><b>${x.total_percent ?? "—"}%</b></td></tr>`).join("")}</table></div>`;
  });
  loadReport("daily_absence", R, "#st-daily");
  loadReport("shift", R, "#st-shift");
  loadReport("public_students", R, "#st-public");
}
function tiles() {
  const t = $("#st-tiles"); if (!t) return;
  const d = t.dataset;
  t.innerHTML = tile("Aktiv talabalar", d.students ? fmt(d.students) : "—", "HEMIS student-stats") + tile("Xodimlar", d.employees ? fmt(d.employees) : "—", "HEMIS employee-stats") +
    tile("Qarzdor talabalar", d.debt ? fmt(d.debt) : "—", d.debtp ? d.debtp + "% talabalardan" : "joriy semestr") + tile("Yangilangan", new Date().toLocaleTimeString("uz-UZ", { hour: "2-digit", minute: "2-digit" }), "kesh 5–30 daq.");
}
ACT.sgb = (el) => { statState.students = el.dataset.v; $$("[data-act=sgb]").forEach((b) => b.classList.toggle("on", b === el)); loadReport("students", { group_by: el.dataset.v }, "#st-students", (e, r) => window.Charts.hbars(e, itemsFrom(r) || [], { limit: 14 })); };
ACT.egb = (el) => { statState.employees = el.dataset.v; $$("[data-act=egb]").forEach((b) => b.classList.toggle("on", b === el)); loadReport("employees", { group_by: el.dataset.v }, "#st-employees", (e, r) => window.Charts.hbars(e, itemsFrom(r) || [], { limit: 14 })); };
ACT.dtype = (el) => { statState.debtType = el.dataset.v; route(); };
ACT.attgo = () => { statState.attFrom = $("#att-from").value; statState.attTo = $("#att-to").value; route(); };
ACT.statref = () => loadAllStats(true);

/* ================================================= MIJOZLAR */
ROUTES.clients = async (v, parts) => {
  if (parts[0]) return clientDetail(v, +parts[0], parts[1] || "main");
  window.onResize = null;
  const cs = await api("GET", "/api/admin/clients");
  S.clientsCache = cs;
  v.innerHTML = head("Mijozlar", "HEMIS ga gateway orqali ulanadigan tashqi tizimlar va ularning kalitlari",
    can("superadmin", "admin") ? `<button class="primary" data-act="newclient">+ Yangi mijoz</button>` : "") + `
    <div class="card"><div class="row" style="margin-bottom:10px"><input placeholder="Qidirish…" data-inp="cfilter" style="width:260px"></div>
    <div class="table-wrap"><table id="ctable"><tr><th>Mijoz</th><th>Holat</th><th>Kalit</th><th>Doira</th><th class="num">Endpoint</th><th class="num">24 soat</th><th class="num">Limit (s / daq)</th><th>Oxirgi faollik</th></tr>
    ${cs.map((c) => `<tr class="click" data-act="go" data-href="#/clients/${c.id}" data-q="${esc((c.name + " " + c.description + " " + c.key_prefix).toLowerCase())}">
      <td><b>${esc(c.name)}</b><div class="muted small">${esc(c.description || c.contact || "")}</div></td>
      <td>${clientStatus(c)}</td><td class="mono">hg_${esc(c.key_prefix)}_…</td>
      <td>${Object.keys(c.scope || {}).length ? Object.entries(c.scope).map(([k, v]) => `<span class="chip">${k}: ${v.join(",")}</span>`).join(" ") : '<span class="muted">butun OTM</span>'}</td>
      <td class="num">${c.permissions_count}</td><td class="num">${fmt(c.requests_24h)}${c.errors_24h ? ` <span class="pill serious">${c.errors_24h}</span>` : ""}</td>
      <td class="num">${c.rate_per_second || "∞"} / ${c.rate_per_minute || "∞"}</td><td>${ago(c.last_used_at)}</td></tr>`).join("") || '<tr><td colspan=8 class="empty">Hali mijoz qo\'shilmagan</td></tr>'}
    </table></div></div>`;
};
CHG.cfilter = (el) => { const q = el.value.toLowerCase(); $$("#ctable tr[data-q]").forEach((r) => (r.style.display = r.dataset.q.includes(q) ? "" : "none")); };
function clientStatus(c) {
  if (!c.is_active) return '<span class="pill bad">o\'chirilgan</span>';
  if (c.suspended_until && new Date(c.suspended_until) > new Date()) return '<span class="pill bad">to\'xtatilgan</span>';
  if (c.expires_at && new Date(c.expires_at) < new Date()) return '<span class="pill bad">muddati o\'tgan</span>';
  if (c.expires_at && new Date(c.expires_at) - Date.now() < 7 * 864e5) return '<span class="pill warn">muddati yaqin</span>';
  return '<span class="pill good">faol</span>';
}

function clientForm(c = {}) {
  const meta = S.meta;
  const sc = c.scope || {};
  return `<div class="grid g2">
    <label class="f"><span>Nomi *</span><input name="name" value="${esc(c.name || "")}" required maxlength="128"></label>
    <label class="f"><span>Mas'ul shaxs / aloqa</span><input name="contact" value="${esc(c.contact || "")}" placeholder="F.I.Sh, telefon, telegram"></label>
  </div>
  <label class="f"><span>Tavsif (qaysi tizim, nima uchun)</span><input name="description" value="${esc(c.description || "")}"></label>
  <div class="grid g4">
    <label class="f"><span>Soniyalik limit (0 = cheksiz)</span><input name="rate_per_second" type="number" min="0" max="1000" value="${c.rate_per_second ?? 10}"></label>
    <label class="f"><span>Daqiqalik limit (0 = cheksiz)</span><input name="rate_per_minute" type="number" min="0" value="${c.rate_per_minute ?? 60}"></label>
    <label class="f"><span>Kunlik kvota (0 = cheksiz)</span><input name="daily_quota" type="number" min="0" value="${c.daily_quota ?? 10000}"></label>
    <label class="f"><span>Kalit amal qilish muddati</span><input name="expires_at" type="date" value="${c.expires_at ? c.expires_at.slice(0, 10) : ""}"></label>
  </div>
  <div class="grid g2">
    <label class="f"><span>Ruxsat etilgan IP manzillar (har qatorda bittasi, CIDR mumkin; bo'sh = hammasi)</span><textarea name="allowed_ips" placeholder="195.158.10.20&#10;10.10.0.0/16">${esc((c.allowed_ips || []).join("\n"))}</textarea></label>
    <label class="f"><span>Brauzer domenlari — CORS (bo'sh = faqat server)</span><textarea name="allowed_origins" placeholder="https://portal.otm.uz">${esc((c.allowed_origins || []).join("\n"))}</textarea></label>
  </div>
  <h3>Ma'lumot doirasi (scope)</h3>
  <p class="muted small" style="margin-top:-4px">Masalan fakultet ID = 7 bersangiz, mijoz barcha endpointlarda faqat 7-fakultet ma'lumotini oladi — gateway filtrni majburan qo'yadi va boshqa qiymatni rad etadi. Bir nechta qiymat vergul bilan.</p>
  <div class="grid g4">${Object.entries(meta.scope_keys).map(([k, l]) => `<label class="f"><span>${l} ID</span><input name="scope_${k}" value="${esc((sc[k] || []).join(","))}" placeholder="—"></label>`).join("")}</div>
  <label class="chk"><input type="checkbox" name="strict_scope" ${c.strict_scope !== false ? "checked" : ""}> Qat'iy doira: doira bilan cheklab bo'lmaydigan endpointlarni bloklash</label><br>
  <label class="chk"><input type="checkbox" name="allow_personal_data" ${c.allow_personal_data ? "checked" : ""}> Shaxsiy ma'lumotlarga ruxsat (PINFL, pasport, telefon, manzil…) — endpoint darajasida ham yoqilishi kerak</label><br>
  <label class="chk"><input type="checkbox" name="is_active" ${c.is_active !== false ? "checked" : ""}> Faol</label>
  <h3 class="mt">Kalit o'g'irlanishidan himoya</h3>
  <label class="f" style="max-width:420px"><span>10 daqiqada maksimal turli IP soni (bo'sh = umumiy sozlama, 0 = o'chiq)</span><input name="max_distinct_ips" type="number" min="0" value="${c.max_distinct_ips ?? ""}" placeholder="umumiy sozlama"></label>
  <p class="muted small" style="margin-top:-6px">Kalit bundan ko'p turli IP dan ishlatilsa, mijoz avtomatik vaqtincha to'xtatiladi va Telegramga xabar keladi. IP manzillari cheklangan mijozlarda tekshirilmaydi.</p>
  <h3 class="mt">API hujjatlari (Swagger) ga kirish</h3>
  <div class="grid g2"><label class="f"><span>Docs login ${c.id ? "" : "(bo'sh qoldirilsa avtomatik yaratiladi)"}</span><input name="docs_username" value="${esc(c.docs_username || "")}" pattern="[a-z0-9_.\\-]{3,64}" placeholder="masalan: kimyo_bot"></label>
  <div><label class="chk" style="margin-top:26px"><input type="checkbox" name="docs_enabled" ${c.docs_enabled !== false ? "checked" : ""}> Docs sahifasiga kirish yoqilgan</label></div></div>`;
}
function readClientForm(f) {
  const fd = new FormData(f), g = (k) => (fd.get(k) || "").toString().trim();
  const lines = (k) => g(k).split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
  const scope = {};
  Object.keys(S.meta.scope_keys).forEach((k) => { const v = lines("scope_" + k); if (v.length) scope[k] = v; });
  return {
    name: g("name"), description: g("description"), contact: g("contact"), is_active: fd.has("is_active"),
    expires_at: g("expires_at") ? g("expires_at") + "T23:59:59Z" : null, allowed_ips: lines("allowed_ips"), allowed_origins: lines("allowed_origins"),
    rate_per_second: +g("rate_per_second") || 0, rate_per_minute: +g("rate_per_minute") || 0, daily_quota: +g("daily_quota") || 0, scope, strict_scope: fd.has("strict_scope"), allow_personal_data: fd.has("allow_personal_data"),
    docs_username: g("docs_username").toLowerCase() || null, docs_enabled: fd.has("docs_enabled"),
    max_distinct_ips: g("max_distinct_ips") === "" ? null : +g("max_distinct_ips"),
  };
}
ACT.newclient = async () => {
  await loadMeta();
  modal(`<form data-submit="createclient"><h2>Yangi mijoz</h2>${clientForm()}<div class="row end mt"><button type="button" data-act="close">Bekor</button><button class="primary">Yaratish va kalit olish</button></div></form>`, true);
};
ACT.createclient = (f) => run(async () => {
  const r = await api("POST", "/api/admin/clients", readClientForm(f));
  showKey(r.api_key, r.client.id, true, { u: r.docs_username, p: r.docs_password });
});
function docsBox(d) {
  return `<h3 class="mt">API hujjatlari (Swagger)</h3>
    <table><tr><th>Manzil</th><td class="mono">${esc(location.origin)}/docs</td></tr><tr><th>Login</th><td class="mono" id="dlu">${esc(d.u)}</td></tr><tr><th>Parol</th><td class="mono" id="dlp">${esc(d.p)}</td></tr></table>
    <div class="row mt"><button data-act="copy" data-text="${esc(`Hujjatlar: ${location.origin}/docs\nLogin: ${d.u}\nParol: ${d.p}`)}">Docs ma'lumotlarini nusxalash</button></div>`;
}
function showKey(key, cid, isNew, docs) {
  modal(`<h2>${isNew ? "Mijoz yaratildi" : "Yangi kalit"}</h2>
    <div class="alert">Kalit${docs ? " va docs paroli" : ""} faqat <b>hozir bir marta</b> ko'rsatiladi. Bazada faqat xeshi saqlanadi — yo'qotilsa, yangisini yaratish kerak.</div>
    <div class="keybox" id="newkey">${esc(key)}</div>
    <div class="row mt"><button data-act="copy" data-target="#newkey">Kalitni nusxalash</button></div>
    ${docs ? docsBox(docs) : ""}
    <h3 class="mt">Ishlatish</h3>
    <pre class="json">curl -H "X-Gateway-Key: ${esc(key)}" \\
  "${location.origin}/rest/v1/data/student-list?limit=20"</pre>
    <div class="row end mt"><button class="primary" data-act="go" data-href="#/clients/${cid}/perms">${isNew ? "Ruxsatlarni sozlash →" : "Yopish"}</button></div>`);
  $("#modal [data-act=go]").addEventListener("click", closeModal);
}

async function clientDetail(v, cid, tab) {
  window.onResize = null;
  await loadMeta();
  const c = await api("GET", "/api/admin/clients/" + cid);
  const T = [["main", "Asosiy"], ["perms", `Ruxsatlar (${c.permissions.length})`], ["test", "Sinov"], ["logs", "Jurnal"]];
  v.innerHTML = head(esc(c.name), `${clientStatus(c)} &nbsp;<span class="mono">hg_${esc(c.key_prefix)}_…</span> &nbsp;·&nbsp; yaratilgan ${dt(c.created_at)} (${esc(c.created_by)}) · oxirgi faollik: ${ago(c.last_used_at)} · docs: <span class="mono">${esc(c.docs_username || "—")}</span>${c.docs_enabled ? "" : " (o'chiq)"}, kirgan: ${ago(c.docs_last_login_at)}`,
    `<a class="btn" href="#/clients">← Ro'yxat</a>${can("superadmin", "admin") ? `<button data-act="csuspend" data-id="${cid}">To'xtatish</button><button data-act="docspw" data-id="${cid}">Docs paroli</button><button data-act="rotate" data-id="${cid}">Kalitni almashtirish</button>` : ""}${can("superadmin") ? `<button class="danger" data-act="delclient" data-id="${cid}">O'chirish</button>` : ""}`) +
    (c.suspended_until && new Date(c.suspended_until) > new Date() ? `<div class="alert bad row"><span><b>Mijoz ${dt(c.suspended_until)} gacha to'xtatilgan.</b> ${esc(c.suspend_reason)}</span><span class="spacer"></span>${can("superadmin", "admin") ? `<button class="sm" data-act="cresume" data-id="${cid}">Qayta yoqish</button>` : ""}</div>` : "") +
    `<div class="tabs">${T.map(([k, l]) => `<button class="${k === tab ? "on" : ""}" data-act="go" data-href="#/clients/${cid}/${k}">${l}</button>`).join("")}</div><div id="ctab"></div>`;
  const t = $("#ctab");
  if (tab === "main") {
    t.innerHTML = `<form class="card" data-submit="saveclient" data-id="${cid}">${clientForm(c)}${can("superadmin", "admin") ? `<div class="row end mt"><button class="primary">Saqlash</button></div>` : ""}</form>`;
  } else if (tab === "perms") await permEditor(t, c);
  else if (tab === "test") {
    t.innerHTML = `<div class="card"><h2>So'rovni sinash (HEMIS ga yuborilmaydi)</h2><p class="muted small" style="margin-top:-6px">Mijoz shu URL ni chaqirsa gateway nima qiladi: o'tkazadimi, HEMIS ga qanday filtr bilan ketadi, qaysi maydonlar yashiriladi.</p>
      <form data-submit="simulate" data-id="${cid}" class="row"><select name="method"><option>GET</option><option>POST</option></select><input name="url" style="flex:1;min-width:240px" placeholder="/rest/v1/data/student-list?_department=7&limit=50" required><button class="primary">Tekshirish</button></form>
      <div id="simres" class="mt"></div></div>`;
  } else if (tab === "logs") await logsView(t, { client_id: cid }, true);
}
ACT.saveclient = (f) => run(async () => { await api("PUT", "/api/admin/clients/" + f.dataset.id, readClientForm(f)); toast("Saqlandi"); route(); });
ACT.rotate = (el) => {
  modal(`<h2>Kalitni almashtirish</h2><p>Eski kalit <b>darhol</b> ishlamay qoladi. Mijoz tizimida yangi kalitni o'rnatish kerak bo'ladi.</p><div class="row end"><button data-act="close">Bekor</button><button class="primary" data-act="rotatego" data-id="${el.dataset.id}">Almashtirish</button></div>`);
};
ACT.docspw = (el) => modal(`<h2>Docs parolini yangilash</h2><p>Mijozga hujjatlar sahifasi uchun yangi parol yaratiladi. Eski parol va ochiq sessiyalar darhol bekor bo'ladi. API kaliti o'zgarmaydi.</p><div class="row end"><button data-act="close">Bekor</button><button class="primary" data-act="docspwgo" data-id="${el.dataset.id}">Yangi parol yaratish</button></div>`);
ACT.docspwgo = (el) => run(async () => {
  const r = await api("POST", `/api/admin/clients/${el.dataset.id}/docs-password`);
  modal(`<h2>Yangi docs paroli</h2><div class="alert">Parol faqat hozir ko'rsatiladi.</div>${docsBox({ u: r.docs_username, p: r.docs_password })}<div class="row end mt"><button class="primary" data-act="close">Yopish</button></div>`);
});
ACT.rotatego = (el) => run(async () => { const r = await api("POST", `/api/admin/clients/${el.dataset.id}/rotate-key`); showKey(r.api_key, el.dataset.id, false); });
ACT.delclient = (el) => modal(`<h2>Mijozni o'chirish</h2><p>Mijoz va uning barcha ruxsatlari butunlay o'chiriladi. Jurnal yozuvlari saqlanib qoladi.</p><div class="row end"><button data-act="close">Bekor</button><button class="primary" style="background:var(--critical)" data-act="delclientgo" data-id="${el.dataset.id}">O'chirish</button></div>`);
ACT.delclientgo = (el) => run(async () => { await api("DELETE", "/api/admin/clients/" + el.dataset.id); closeModal(); toast("O'chirildi"); location.hash = "#/clients"; });
ACT.simulate = (f) => run(async () => {
  const fd = Object.fromEntries(new FormData(f));
  const r = await api("POST", `/api/admin/clients/${f.dataset.id}/simulate`, fd);
  $("#simres").innerHTML = r.ok
    ? `<div class="alert good"><b>Ruxsat beriladi.</b> Endpoint: <span class="mono">${esc(r.endpoint.path)}</span> (${authLabel(r.endpoint.auth_mode)})</div>
       <h3>HEMIS ga ketadigan so'rov</h3><pre class="json">${esc(r.endpoint.path)}${r.upstream_query ? "?" + esc(r.upstream_query) : ""}</pre>
       <h3 class="mt">Javobdan olib tashlanadigan maydonlar</h3><div class="chips">${(r.hidden_fields || []).map((h) => `<span class="chip">${esc(h)}</span>`).join("") || '<span class="muted">yo\'q</span>'}</div>`
    : `<div class="alert bad"><b>Rad etiladi:</b> ${esc(r.message)} <span class="mono muted">(${esc(r.code)})</span></div>`;
});

/* ---------- ruxsatlar muharriri ---------- */
let PE = null; // {cid, client, perms: Map, open:Set, q, onlyOn}
async function permEditor(t, c) {
  const eps = await loadEndpoints();
  PE = { cid: c.id, client: c, perms: new Map(c.permissions.map((p) => [p.endpoint_id, { ...p }])), open: new Set(), openG: new Set(), q: "", onlyOn: false, dirty: false };
  const others = (S.clientsCache || await api("GET", "/api/admin/clients")).filter((x) => x.id !== c.id);
  t.innerHTML = `${Object.keys(c.scope || {}).length ? `<div class="alert">Mijoz doirasi: ${Object.entries(c.scope).map(([k, v]) => `<b>${S.meta.scope_keys[k]}</b> = ${v.join(", ")}`).join("; ")}. Doira filtrlari har bir endpointga avtomatik qo'llanadi${c.strict_scope ? "; doira bilan cheklab bo'lmaydigan endpointlar <b>bloklanadi</b>" : ""}.</div>` : ""}
    <div class="row" style="margin-bottom:12px"><input placeholder="Endpoint qidirish (yo'l yoki tavsif)…" data-inp="pq" style="flex:1;min-width:220px"><label class="chk"><input type="checkbox" data-chg="ponly"> Faqat yoqilganlar</label>
    ${others.length && can("superadmin", "admin") ? `<select data-chg="pcopy"><option value="">Boshqa mijozdan nusxa…</option>${others.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select>` : ""}</div>
    <div id="pgroups"></div>
    ${can("superadmin", "admin") ? `<div class="sticky-bar row"><span id="pcount" class="muted"></span><span class="spacer"></span><button class="primary" data-act="psave">Ruxsatlarni saqlash</button></div>` : ""}`;
  drawPerms();
}
function drawPerms() {
  const eps = S.endpoints, q = PE.q.toLowerCase();
  const groups = {};
  for (const e of eps) {
    if (PE.onlyOn && !PE.perms.has(e.id)) continue;
    if (q && !(e.path.toLowerCase().includes(q) || (e.summary || "").toLowerCase().includes(q))) continue;
    (groups[e.group] = groups[e.group] || []).push(e);
  }
  const html = Object.entries(groups).map(([g, list]) => {
    const on = list.filter((e) => PE.perms.has(e.id)).length;
    const open = PE.openG.has(g) || !!q || PE.onlyOn;
    return `<div class="grp"><header data-act="pgrp" data-g="${esc(g)}"><b>${open ? "▾" : "▸"} ${esc(g)}</b><span class="cnt">${on} / ${list.length} yoqilgan</span><span class="spacer"></span>
      ${can("superadmin", "admin") ? `<button class="sm" data-act="pall" data-g="${esc(g)}" data-v="1">Hammasi</button><button class="sm" data-act="pall" data-g="${esc(g)}" data-v="0">Hech biri</button>` : ""}</header>
      ${open ? list.map(epRow).join("") : ""}</div>`;
  }).join("") || '<div class="empty">Topilmadi</div>';
  $("#pgroups").innerHTML = html;
  const pc = $("#pcount"); if (pc) pc.textContent = `${PE.perms.size} ta endpoint yoqilgan${PE.dirty ? " · saqlanmagan o'zgarishlar bor" : ""}`;
}
function scopeWarning(e) {
  const sc = PE.client.scope || {};
  if (!Object.keys(sc).length || e.auth_mode !== "admin") return "";
  const keys = new Set(e.params.map((p) => p.scope_key).filter(Boolean));
  const miss = Object.keys(sc).filter((k) => !keys.has(k));
  if (!miss.length) return "";
  return PE.client.strict_scope ? `<span class="pill bad" title="Bu endpointda ${miss.join(", ")} filtri yo'q">doira: bloklanadi</span>` : `<span class="pill warn">doira qo'llanmaydi</span>`;
}
function epRow(e) {
  const p = PE.perms.get(e.id), on = !!p, open = on && PE.open.has(e.id);
  const ro = !can("superadmin", "admin") ? "disabled" : "";
  let cfg = "";
  if (open) {
    const qp = e.params.filter((x) => x.in === "query");
    const all = p.allowed_params == null;
    cfg = `<div class="cfg">
      <div><h3>Ruxsat etilgan filtrlar</h3>
        <label class="chk"><input type="radio" name="pm${e.id}" data-chg="pmode" data-id="${e.id}" value="all" ${all ? "checked" : ""} ${ro}> Hammasi</label>
        <label class="chk"><input type="radio" name="pm${e.id}" data-chg="pmode" data-id="${e.id}" value="sel" ${!all ? "checked" : ""} ${ro}> Faqat tanlanganlar</label>
        <div class="params mt">${qp.map((x) => `<label class="${x.scope_key ? "scoped" : ""}" title="${esc(x.description)}${x.scope_key ? " · doira: " + x.scope_key : ""}"><input type="checkbox" data-chg="pparam" data-id="${e.id}" value="${esc(x.name)}" ${all || p.allowed_params.includes(x.name) ? "checked" : ""} ${all || ro ? "disabled" : ""}>${esc(x.name)}</label>`).join("") || '<span class="muted">Filtr yo\'q</span>'}</div>
        <p class="muted small">Ko'k ramkali filtrlar — doira (scope) filtrlari, mijoz doirasi bo'lsa avtomatik nazorat qilinadi.</p></div>
      <div><h3>Qulflangan filtrlar</h3><textarea data-chg="plock" data-id="${e.id}" placeholder="_education_year=2024&#10;_level=11,12" ${ro}>${esc(Object.entries(p.locked_params || {}).map(([k, v]) => k + "=" + v.join(",")).join("\n"))}</textarea>
        <p class="muted small">Mijoz faqat shu qiymatlarni yubora oladi. Bitta qiymat bo'lsa — gateway o'zi qo'yadi.</p>
        <div class="grid g2"><label class="f"><span>Max limit (1–200)</span><input type="number" min="1" max="200" data-chg="pmax" data-id="${e.id}" value="${p.max_limit ?? ""}" placeholder="200" ${ro}></label>
        <label class="f"><span>Yashiriladigan maydonlar</span><input data-chg="phide" data-id="${e.id}" value="${esc((p.hidden_fields || []).join(", "))}" placeholder="salary, data.items.address" ${ro}></label></div>
        <label class="chk"><input type="checkbox" data-chg="ppers" data-id="${e.id}" ${p.allow_personal ? "checked" : ""} ${ro}> Shaxsiy ma'lumotlarni ko'rsatish ${PE.client.allow_personal_data ? "" : '<span class="muted small">(mijoz darajasida o\'chiq)</span>'}</label></div>
    </div>`;
  }
  const custom = on && (p.allowed_params != null || Object.keys(p.locked_params || {}).length || p.max_limit || (p.hidden_fields || []).length || p.allow_personal);
  return `<div class="ep ${on ? "on" : ""}"><div class="line">
    <input type="checkbox" data-chg="pon" data-id="${e.id}" ${on ? "checked" : ""} ${ro} aria-label="yoqish">
    <span class="m ${e.method}">${e.method}</span>
    <div><div class="path">${esc(e.path)}</div><div class="sum">${esc(e.summary)}</div></div>
    <div class="row">${!e.in_spec ? '<span class="pill bad">hujjatdan olib tashlangan</span>' : ""}${!e.is_enabled ? '<span class="pill bad">global o\'chiq</span>' : ""}${on ? scopeWarning(e) : ""}${riskPill(e.risk)}<span class="pill plain">${authLabel(e.auth_mode)}</span>${on ? `<button class="sm" data-act="pcfg" data-id="${e.id}">${open ? "Yopish" : custom ? "Sozlangan ✓" : "Sozlash"}</button>` : ""}</div>
  </div>${cfg}</div>`;
}
const newPerm = (id) => ({ endpoint_id: id, allowed_params: null, locked_params: {}, max_limit: null, hidden_fields: [], allow_personal: false });
const dirty = () => { PE.dirty = true; };
CHG.pq = (el) => { PE.q = el.value; drawPerms(); };
CHG.ponly = (el) => { PE.onlyOn = el.checked; drawPerms(); };
ACT.pgrp = (el, ev) => { if (ev.target.closest("button")) return; const g = el.dataset.g; PE.openG.has(g) ? PE.openG.delete(g) : PE.openG.add(g); drawPerms(); };
ACT.pall = (el) => {
  const g = el.dataset.g, on = el.dataset.v === "1", q = PE.q.toLowerCase();
  S.endpoints.filter((e) => e.group === g && (!q || e.path.toLowerCase().includes(q) || (e.summary || "").toLowerCase().includes(q))).forEach((e) => { if (on && !PE.perms.has(e.id)) PE.perms.set(e.id, newPerm(e.id)); if (!on) PE.perms.delete(e.id); });
  PE.openG.add(g); dirty(); drawPerms();
};
CHG.pon = (el) => { const id = +el.dataset.id; el.checked ? PE.perms.set(id, newPerm(id)) : PE.perms.delete(id); dirty(); drawPerms(); };
ACT.pcfg = (el) => { const id = +el.dataset.id; PE.open.has(id) ? PE.open.delete(id) : PE.open.add(id); drawPerms(); };
CHG.pmode = (el) => {
  const p = PE.perms.get(+el.dataset.id), e = S.endpoints.find((x) => x.id === +el.dataset.id);
  p.allowed_params = el.value === "all" ? null : e.params.filter((x) => x.in === "query").map((x) => x.name);
  dirty(); drawPerms();
};
CHG.pparam = (el) => {
  const p = PE.perms.get(+el.dataset.id); const s = new Set(p.allowed_params || []);
  el.checked ? s.add(el.value) : s.delete(el.value); p.allowed_params = [...s]; dirty();
};
CHG.plock = (el) => {
  const p = PE.perms.get(+el.dataset.id), out = {};
  el.value.split("\n").map((l) => l.trim()).filter(Boolean).forEach((l) => { const [k, ...r] = l.split("="); const vals = r.join("=").split(",").map((x) => x.trim()).filter(Boolean); if (k.trim() && vals.length) out[k.trim()] = vals; });
  p.locked_params = out; dirty();
};
CHG.pmax = (el) => { PE.perms.get(+el.dataset.id).max_limit = el.value ? +el.value : null; dirty(); };
CHG.phide = (el) => { PE.perms.get(+el.dataset.id).hidden_fields = el.value.split(",").map((x) => x.trim()).filter(Boolean); dirty(); };
CHG.ppers = (el) => { PE.perms.get(+el.dataset.id).allow_personal = el.checked; dirty(); };
CHG.pcopy = (el) => {
  if (!el.value) return;
  const name = el.options[el.selectedIndex].text, src = el.value; el.value = "";
  modal(`<h2>Ruxsatlarni nusxalash</h2><p><b>${esc(name)}</b> mijozining barcha ruxsatlari bu mijozga ko'chiriladi. Joriy ruxsatlar o'chiriladi.</p><div class="row end"><button data-act="close">Bekor</button><button class="primary" data-act="pcopygo" data-src="${src}">Nusxalash</button></div>`);
};
ACT.pcopygo = (el) => run(async () => { const r = await api("POST", `/api/admin/clients/${PE.cid}/copy-from/${el.dataset.src}`); closeModal(); toast(`${r.count} ta ruxsat ko'chirildi`); route(); });
ACT.psave = () => run(async () => {
  const r = await api("PUT", `/api/admin/clients/${PE.cid}/permissions`, [...PE.perms.values()]);
  PE.dirty = false; toast(`Saqlandi: ${r.count} ta endpoint`);
  const b = $(".tabs button:nth-child(2)"); if (b) b.textContent = `Ruxsatlar (${r.count})`; drawPerms();
});
window.addEventListener("beforeunload", (e) => { if (PE && PE.dirty) { e.preventDefault(); e.returnValue = ""; } });

/* ================================================= ENDPOINTLAR */
let EPF = { q: "", g: "", risk: "" };
ROUTES.endpoints = async (v) => {
  window.onResize = null;
  const eps = await loadEndpoints(true);
  const groups = [...new Set(eps.map((e) => e.group))];
  v.innerHTML = head("Endpointlar katalogi", `HEMIS API hujjatidan import qilingan ${eps.filter((e) => e.in_spec).length} ta endpoint${eps.some((e) => !e.in_spec) ? ` (+${eps.filter((e) => !e.in_spec).length} tasi hujjatdan olib tashlangan)` : ""}. Global holat, avtorizatsiya turi, kesh va doira filtrlari shu yerda sozlanadi.`,
    can("superadmin") ? `<button data-act="syncopen">Avto-sinxronlash</button><button data-act="specversions">Versiyalar</button><button class="primary" data-act="specopen">HEMIS docs yangilash</button><button data-act="cacheclear">Keshni tozalash</button>` : "") + `
    <div id="syncbar"></div>
    <div class="card"><div class="row" style="margin-bottom:10px"><input placeholder="Qidirish…" data-inp="epq" value="${esc(EPF.q)}" style="flex:1;min-width:200px">
      <select data-chg="epg"><option value="">Barcha guruhlar</option>${groups.map((g) => `<option ${g === EPF.g ? "selected" : ""}>${esc(g)}</option>`).join("")}</select>
      <select data-chg="epr"><option value="">Har qanday xavf</option><option value="high" ${EPF.risk === "high" ? "selected" : ""}>Yuqori</option><option value="medium" ${EPF.risk === "medium" ? "selected" : ""}>O'rta</option><option value="low" ${EPF.risk === "low" ? "selected" : ""}>Past</option><option value="removed" ${EPF.risk === "removed" ? "selected" : ""}>Hujjatdan olib tashlanganlar</option></select></div>
    <div class="table-wrap"><table id="eptable"></table></div></div>`;
  drawEps();
  syncBar();
};
function drawEps() {
  const q = EPF.q.toLowerCase();
  const list = S.endpoints.filter((e) => (!EPF.g || e.group === EPF.g) && (!EPF.risk || (EPF.risk === "removed" ? !e.in_spec : e.risk === EPF.risk)) && (!q || e.path.toLowerCase().includes(q) || (e.summary || "").toLowerCase().includes(q)));
  $("#eptable").innerHTML = `<tr><th></th><th>Endpoint</th><th>Guruh</th><th>Avtorizatsiya</th><th>Xavf</th><th class="num">Kesh</th><th class="num">Mijozlar</th><th>Doira filtrlari</th></tr>` +
    list.map((e) => `<tr class="click" data-act="epedit" data-id="${e.id}"><td><span class="m ${e.method}">${e.method}</span></td><td><div class="mono">${esc(e.path)}</div><div class="muted small">${esc(e.summary)}</div></td><td class="small">${esc(e.group)}</td>
      <td>${!e.in_spec ? '<span class="pill bad">hujjatda yo\'q</span>' : e.is_enabled ? `<span class="pill plain">${authLabel(e.auth_mode)}</span>` : '<span class="pill bad">o\'chirilgan</span>'}</td><td>${riskPill(e.risk)}</td><td class="num">${e.cache_ttl ? e.cache_ttl + "s" : "—"}</td><td class="num">${e.clients}</td>
      <td>${e.params.filter((p) => p.scope_key).map((p) => `<span class="chip">${esc(p.name)}→${p.scope_key}</span>`).join(" ")}</td></tr>`).join("");
}
CHG.epq = (el) => { EPF.q = el.value; drawEps(); };
CHG.epg = (el) => { EPF.g = el.value; drawEps(); };
CHG.epr = (el) => { EPF.risk = el.value; drawEps(); };
ACT.epedit = async (el) => {
  await loadMeta();
  const e = S.endpoints.find((x) => x.id === +el.dataset.id), ro = can("superadmin") ? "" : "disabled";
  const so = (cur) => `<option value="">—</option>` + Object.entries(S.meta.scope_keys).map(([k, l]) => `<option value="${k}" ${cur === k ? "selected" : ""}>${l}</option>`).join("");
  modal(`<form data-submit="epsave" data-id="${e.id}"><h2><span class="m ${e.method}">${e.method}</span> <span class="mono">${esc(e.path)}</span></h2><p class="muted">${esc(e.summary)}</p>
    ${e.description ? `<details><summary class="small">Tavsif</summary><p class="small" style="white-space:pre-wrap">${esc(e.description)}</p></details>` : ""}
    <div class="grid g3 mt">
      <label class="f"><span>Avtorizatsiya</span><select name="auth_mode" ${ro}>${Object.entries(S.meta.auth_modes).map(([k, l]) => `<option value="${k}" ${e.auth_mode === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
      <label class="f"><span>Xavf darajasi</span><select name="risk" ${ro}>${["low", "medium", "high"].map((r) => `<option value="${r}" ${e.risk === r ? "selected" : ""}>${r}</option>`).join("")}</select></label>
      <label class="f"><span>Kesh (soniya, 0 = yo'q)</span><input name="cache_ttl" type="number" min="0" max="86400" value="${e.cache_ttl}" ${ro}></label></div>
    <label class="chk"><input type="checkbox" name="is_enabled" ${e.is_enabled ? "checked" : ""} ${ro}> Endpoint yoqilgan (o'chirilsa hech bir mijoz foydalana olmaydi)</label>
    <h3 class="mt">Filtrlar va doira bog'lanishi</h3>
    <div class="table-wrap"><table><tr><th>Parametr</th><th>Tavsif</th><th>Doira</th></tr>${e.params.map((p) => `<tr><td class="mono">${esc(p.name)}${p.in === "path" ? ' <span class="muted">(path)</span>' : ""}</td><td class="small">${esc(p.description)}</td><td>${p.in === "query" ? `<select name="sk_${esc(p.name)}" ${ro}>${so(p.scope_key)}</select>` : ""}</td></tr>`).join("") || '<tr><td colspan=3 class="muted">Parametr yo\'q</td></tr>'}</table></div>
    <div class="row end mt"><button type="button" data-act="close">Yopish</button>${ro ? "" : '<button class="primary">Saqlash</button>'}</div></form>`, true);
};
ACT.epsave = (f) => run(async () => {
  const fd = new FormData(f), scope_map = {};
  for (const [k, v] of fd.entries()) if (k.startsWith("sk_")) scope_map[k.slice(3)] = v || null;
  const r = await api("PUT", "/api/admin/endpoints/" + f.dataset.id, { is_enabled: fd.has("is_enabled"), auth_mode: fd.get("auth_mode"), risk: fd.get("risk"), cache_ttl: +fd.get("cache_ttl") || 0, scope_map });
  const i = S.endpoints.findIndex((x) => x.id === r.id); S.endpoints[i] = { ...S.endpoints[i], ...r, clients: S.endpoints[i].clients };
  closeModal(); toast("Saqlandi"); drawEps();
});
CHG.epsync = (el) => run(async () => {
  const fd = new FormData(); fd.append("file", el.files[0]);
  const r = await api("POST", "/api/admin/endpoints/sync", fd, true);
  toast(`Katalog yangilandi: +${r.added} yangi, ${r.updated} yangilangan`); route();
});
ACT.cacheclear = () => run(async () => { const r = await api("POST", "/api/admin/cache/clear"); toast(`Kesh tozalandi (${r.deleted})`); });

/* ================================================= JURNAL */
ROUTES.logs = async (v) => {
  window.onResize = null;
  const params = Object.fromEntries(new URLSearchParams(location.hash.split("?")[1] || ""));
  v.innerHTML = head("So'rovlar jurnali", "Gateway orqali o'tgan va rad etilgan barcha so'rovlar") + '<div id="logbox"></div>';
  await logsView($("#logbox"), params, false);
};
let LOGF = {};
async function logsView(el, fixed, inClient) {
  LOGF = { ...fixed, page: 1 };
  const cs = inClient ? [] : (S.clientsCache || (S.clientsCache = await api("GET", "/api/admin/clients")));
  el.innerHTML = `<div class="card"><form class="row" data-submit="logfilter" style="margin-bottom:10px">
    ${inClient ? "" : `<select name="client_id"><option value="">Barcha mijozlar</option>${cs.map((c) => `<option value="${c.id}" ${+LOGF.client_id === c.id ? "selected" : ""}>${esc(c.name)}</option>`).join("")}</select>`}
    <select name="status"><option value="">Barcha holatlar</option><option value="ok">Muvaffaqiyatli</option><option value="denied">Rad etilgan</option><option value="error">Xato (5xx)</option></select>
    <input name="path" placeholder="Yo'l…" value="${esc(LOGF.path || "")}"><input name="ip" placeholder="IP" value="${esc(LOGF.ip || "")}" style="width:130px">
    <input type="datetime-local" name="date_from"><input type="datetime-local" name="date_to"><button class="primary">Filtrlash</button></form>
    <div id="logtable"></div></div>`;
  await drawLogs();
}
async function drawLogs() {
  const q = new URLSearchParams(Object.entries(LOGF).filter(([, v]) => v !== "" && v != null)).toString();
  const r = await api("GET", "/api/admin/logs?" + q);
  S.logRows = r.items;
  const pages = Math.max(1, Math.ceil(r.total / 50));
  $("#logtable").innerHTML = `<div class="table-wrap"><table><tr><th>Vaqt</th><th>Mijoz</th><th>So'rov</th><th>Holat</th><th>Sabab</th><th class="num">ms</th><th>IP</th></tr>
    ${r.items.map((x, i) => `<tr class="click" data-act="logrow" data-i="${i}"><td class="small" style="white-space:nowrap">${dt(x.ts)}</td><td>${esc(x.client_name || "—")}</td>
      <td><span class="m ${x.method}">${x.method}</span> <span class="mono">${esc(x.path)}</span>${x.query ? `<div class="mono muted small" style="overflow-wrap:anywhere">?${esc(x.query.slice(0, 140))}</div>` : ""}</td>
      <td>${statusPill(x.status)}${x.cache_hit ? ' <span class="pill plain">kesh</span>' : ""}</td><td class="small">${esc(DENY[x.denied_reason] || x.denied_reason || "")}</td><td class="num">${fmt(x.latency_ms)}</td><td class="mono small">${esc(x.ip)}</td></tr>`).join("") || '<tr><td colspan=7 class="empty">Yozuv topilmadi</td></tr>'}</table></div>
    <div class="row mt"><span class="muted">Jami: ${fmt(r.total)}</span><span class="spacer"></span><button class="sm" data-act="logpage" data-d="-1" ${LOGF.page <= 1 ? "disabled" : ""}>← Oldingi</button><span class="small">${LOGF.page} / ${pages}</span><button class="sm" data-act="logpage" data-d="1" ${LOGF.page >= pages ? "disabled" : ""}>Keyingi →</button></div>`;
}
ACT.logfilter = (f) => run(async () => {
  const fd = Object.fromEntries(new FormData(f));
  for (const k of ["date_from", "date_to"]) if (fd[k]) fd[k] = new Date(fd[k]).toISOString();
  LOGF = { ...LOGF, ...fd, page: 1 }; await drawLogs();
});
ACT.logpage = (el) => run(async () => { LOGF.page += +el.dataset.d; await drawLogs(); });
ACT.logrow = (el) => {
  const x = S.logRows[+el.dataset.i];
  modal(`<h2>So'rov #${x.id}</h2><table>${[["Vaqt", dt(x.ts)], ["Mijoz", esc(x.client_name || "—")], ["So'rov", `<span class="m ${x.method}">${x.method}</span> <span class="mono">${esc(x.path)}</span>`],
    ["Query", `<span class="mono" style="overflow-wrap:anywhere">${esc(x.query || "—")}</span>`], ["Gateway javobi", statusPill(x.status)], ["HEMIS javobi", x.upstream_status ? statusPill(x.upstream_status) : "—"],
    ["Sabab", esc((DENY[x.denied_reason] || "") + (x.denied_reason ? ` (${x.denied_reason})` : "—"))], ["Davomiyligi", fmt(x.latency_ms) + " ms"], ["Hajm", bytes(x.bytes)], ["Kesh", x.cache_hit ? "ha" : "yo'q"],
    ["IP", `<span class="mono">${esc(x.ip)}</span>`], ["User-Agent", `<span class="small">${esc(x.user_agent)}</span>`]].map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`).join("")}</table>
    ${x.detail ? `<h3 class="mt">Tafsilot</h3><pre class="json">${esc(x.detail)}</pre>` : ""}<div class="row end mt"><button data-act="close">Yopish</button></div>`);
};

ROUTES.audit = async (v) => {
  window.onResize = null;
  const r = await api("GET", "/api/admin/audit?limit=200");
  v.innerHTML = head("Admin amallari", "Panelda kim, qachon, nima o'zgartirgani (o'chirib bo'lmaydi)") + `<div class="card"><div class="table-wrap"><table><tr><th>Vaqt</th><th>Admin</th><th>Amal</th><th>Obyekt</th><th>Tafsilot</th><th>IP</th></tr>
    ${r.items.map((x) => `<tr><td class="small" style="white-space:nowrap">${dt(x.ts)}</td><td>${esc(x.admin)}</td><td><span class="pill ${x.action.includes("fail") || x.action.includes("delete") ? "serious" : "plain"}">${esc(x.action)}</span></td><td class="mono small">${esc(x.target)}</td><td class="mono small" style="max-width:360px;overflow-wrap:anywhere">${esc(JSON.stringify(x.details)).slice(0, 300)}</td><td class="mono small">${esc(x.ip)}</td></tr>`).join("")}
    </table></div><p class="muted small">Oxirgi 200 ta amal ko'rsatilgan (jami ${fmt(r.total)}).</p></div>`;
};

/* ================================================= SOZLAMALAR */
ROUTES.settings = async (v) => {
  window.onResize = null;
  const s = await api("GET", "/api/admin/settings");
  v.innerHTML = head("Sozlamalar", "HEMIS ulanishi. Tokenlar bazada shifrlangan holda saqlanadi va hech qachon mijozlarga ko'rsatilmaydi.") + `
    <div class="grid g2"><form class="card" data-submit="savesettings">
      ${(s.secret_errors || []).length ? `<div class="alert bad">Saqlangan maxfiy qiymatlarni ochib bo'lmadi (${esc(s.secret_errors.join(", "))}): server kaliti (ENCRYPTION_KEY/SECRET_KEY) o'zgargan. Ularni qayta kiriting.</div>` : ""}
      <h2>HEMIS Backend API</h2>
      <label class="f"><span>HEMIS manzili (OTM student.*.uz manzili; docs havolasini ham qo'yish mumkin)</span><input name="hemis_base_url" value="${esc(s.hemis_base_url)}" placeholder="https://student.otm.uz/rest"></label>
      <label class="f"><span>Admin token (API User roli) ${s.hemis_admin_token_set ? `<span class="pill good">o'rnatilgan ${esc(s.hemis_admin_token_hint)}</span>` : '<span class="pill bad">o\'rnatilmagan</span>'}</span><input name="hemis_admin_token" type="password" autocomplete="off" placeholder="Yangi token (o'zgartirmaslik uchun bo'sh qoldiring)"></label>
      <h2 class="mt">Fast API (ixtiyoriy)</h2>
      <label class="f"><span>Fast API manzili</span><input name="fast_api_url" value="${esc(s.fast_api_url)}" placeholder="https://..."></label>
      <label class="f"><span>Fast API token ${s.fast_api_token_set ? '<span class="pill good">o\'rnatilgan</span>' : ""}</span><input name="fast_api_token" type="password" autocomplete="off" placeholder="o'zgartirmaslik uchun bo'sh"></label>
      <label class="f"><span>HEMIS docs paroli <span class="muted">(HEMIS docs sahifasi parol so'rasa)</span> ${s.docs_password_set ? '<span class="pill good">o\'rnatilgan</span>' : ""}</span><input name="docs_password" type="password" autocomplete="off" placeholder="o'zgartirmaslik uchun bo'sh qoldiring"></label>
      <div class="row end"><button type="button" data-act="testup">Ulanishni tekshirish</button><button type="submit">Saqlash</button><button type="button" class="primary" data-act="setupsync">Saqlash va sinxronlash</button></div>
      <p class="small muted">«Saqlash va sinxronlash» bir bosishda: tokenni tekshiradi, OTM nomi va logotipini, HEMIS API hujjatini (endpointlar va filtrlar) yuklab oladi.</p>
      <div id="testres" class="mt"></div>
      <h2 class="mt">OTM ma'lumotlari</h2>
      <p class="small muted" style="margin-top:-6px">«Saqlash va sinxronlash» bosilganda nomi va logotipi HEMIS dan avtomatik olinadi.</p>
      <div class="row" style="margin-bottom:10px">${s.has_logo ? '<img src="/branding/logo?' + Date.now() + '" alt="logo" style="width:48px;height:48px;object-fit:contain;border-radius:8px;border:1px solid var(--border);background:#fff">' : ""}<b>${esc(s.org_name || "—")}</b></div>
      <label class="f"><span>OTM to'liq nomi</span><input name="org_name" value="${esc(s.org_name)}" placeholder="HEMIS dan avtomatik"></label>
      <div class="grid g2"><label class="f"><span>Qisqa nomi</span><input name="org_short" value="${esc(s.org_short)}" placeholder="${esc(s.org_short_auto || "masalan: TATU")}"></label>
      <label class="f"><span>Gateway ochiq manzili</span><input name="public_base_url" value="${esc(s.public_base_url)}" placeholder="${esc(location.origin)}"></label></div>
    </form>
    <div class="card"><h2>Xavfsizlik bo'yicha eslatma</h2><ul class="small" style="padding-left:18px;margin:0;line-height:1.7">
      <li>HEMIS da <b>API User</b> rolini faqat shu gateway uchun alohida admin foydalanuvchiga bering va tokenni boshqa joyda ishlatmang.</li>
      <li>HEMIS tomonida (agar imkon bo'lsa) Backend API ni faqat shu server IP manziliga cheklang.</li>
      <li>Har bir tashqi tizimga <b>alohida</b> mijoz va kalit bering — umumiy kalit ishlatmang.</li>
      <li>Mijozlarga faqat kerakli endpointlarni yoqing; <span class="pill bad">yuqori xavf</span> endpointlar (yuklab olish, transcript, tizim jurnali) alohida e'tibor talab qiladi.</li>
      <li>Admin panelni <span class="mono">ADMIN_ALLOWED_IPS</span> orqali OTM tarmog'iga cheklang va barcha adminlar uchun 2FA yoqing.</li>
      <li>Kalitlarni muntazam (masalan 6 oyda) almashtiring, ishlatilmayotgan mijozlarni o'chiring.</li></ul></div></div>`;
};
ACT.savesettings = (f) => run(async () => {
  const fd = Object.fromEntries(new FormData(f));
  for (const k of ["hemis_admin_token", "fast_api_token"]) if (!fd[k]) delete fd[k];
  delete fd.docs_password;
  await api("PUT", "/api/admin/settings", fd); toast("Saqlandi"); await loadBrand(); layout(); route();
});
ACT.setupsync = () => run(async () => {
  const f = $("form[data-submit=savesettings]"); const fv = Object.fromEntries(new FormData(f));
  $("#testres").innerHTML = '<div class="alert">Sinxronlanmoqda… (token, OTM profili, HEMIS API hujjati)</div>';
  const extra = {}; for (const k of ["org_name", "org_short", "public_base_url", "fast_api_url"]) extra[k] = fv[k] || "";
  if (fv.fast_api_token) extra.fast_api_token = fv.fast_api_token;
  await api("PUT", "/api/admin/settings", extra);
  const r = await api("POST", "/api/admin/setup/sync", { hemis_base_url: fv.hemis_base_url || "", hemis_admin_token: fv.hemis_admin_token || "", docs_password: fv.docs_password || "" });
  const labels = { save: "Sozlamalar", token: "HEMIS token", profile: "OTM profili", docs: "HEMIS API hujjati" };
  S.endpoints = null; await loadBrand();
  await ROUTES.settings($("#view"));   // yangilangan holatni ko'rsatish (token belgisi, OTM nomi, logo)
  const sb = $(".side .brand"); if (sb) sb.innerHTML = `${brandLogo()}<div>${esc(S.brand.org_short || "HEMIS")} Gateway<small>${esc(location.host)}</small></div>`;
  $("#testres").innerHTML = `<div class="alert ${r.ok ? "good" : "bad"}"><b>${r.ok ? "Sinxronlash muvaffaqiyatli" : "Sinxronlash to'liq bajarilmadi"}</b></div>` +
    r.steps.map((x) => `<div style="display:grid;grid-template-columns:52px 1fr;gap:8px;margin:6px 0;align-items:start"><span class="pill ${x.ok ? "good" : "bad"}">${x.ok ? "OK" : "xato"}</span><span><b>${esc(labels[x.key] || x.key)}:</b> ${esc(x.message)}</span></div>`).join("") +
    (r.steps.some((x) => x.need_password) ? '<div class="alert">HEMIS docs sahifasi parol bilan himoyalangan — yuqoridagi «HEMIS docs paroli» maydoniga parolni kiritib qayta bosing.</div>' : "");
  $("#testres").scrollIntoView({ block: "nearest" });
});
ACT.testup = () => run(async () => {
  $("#testres").innerHTML = '<span class="muted">Tekshirilmoqda…</span>';
  const f = $("form[data-submit=savesettings]"); const fv = f ? Object.fromEntries(new FormData(f)) : {};
  const r = await api("POST", "/api/admin/settings/test", { hemis_base_url: fv.hemis_base_url || "", hemis_admin_token: fv.hemis_admin_token || "" });
  if (r.profile && r.profile.name) { await loadBrand(); }
  $("#testres").innerHTML = `${r.profile && r.profile.name ? `<div class="alert good">OTM: <b>${esc(r.profile.name)}</b> (kod ${esc(r.profile.code)}, ${esc(r.profile.region)})</div>` : ""}<div class="alert ${r.ok ? "good" : "bad"}">${r.ok ? "HEMIS Backend API bilan aloqa bor — token to'g'ri" : "Ulanib bo'lmadi"} (status: ${r.status ?? "—"})${r.hint ? ". " + esc(r.hint) : ""}</div>${r.diag ? `<div class="small muted" style="margin-bottom:8px">Manzil: <span class="mono">${esc(r.diag.base)}</span> · Token: ${esc(r.diag.token_source || "yo'q")} ${esc(r.diag.token_hint)}</div>` : ""}<pre class="json">${esc(typeof r.body === "string" ? r.body : JSON.stringify(r.body, null, 2))}</pre>`;
});

/* ================================================= ADMINLAR */
ROUTES.admins = async (v) => {
  window.onResize = null;
  const list = await api("GET", "/api/admin/admins");
  S.admins = list;
  v.innerHTML = head("Adminlar", "superadmin — hammasi; admin — mijoz va ruxsatlarni boshqaradi; auditor — faqat ko'radi", `<button class="primary" data-act="adminedit">+ Admin qo'shish</button>`) +
    `<div class="card"><table><tr><th>Login</th><th>F.I.Sh</th><th>Rol</th><th>Holat</th><th>2FA</th><th>Oxirgi kirish</th></tr>${list.map((a) => `<tr class="click" data-act="adminedit" data-id="${a.id}"><td class="mono">${esc(a.username)}</td><td>${esc(a.full_name)}</td><td><span class="pill plain">${a.role}</span></td><td>${a.is_active ? '<span class="pill good">faol</span>' : '<span class="pill bad">bloklangan</span>'}</td><td>${a.totp_enabled ? '<span class="pill good">yoqilgan</span>' : '<span class="pill warn">yo\'q</span>'}</td><td>${dt(a.last_login_at)}</td></tr>`).join("")}</table></div>`;
};
ACT.adminedit = (el) => {
  const a = (S.admins || []).find((x) => x.id === +el.dataset.id) || { role: "admin", is_active: true };
  modal(`<form data-submit="adminsave" data-id="${a.id || ""}"><h2>${a.id ? "Adminni tahrirlash" : "Yangi admin"}</h2>
    <label class="f"><span>Login</span><input name="username" value="${esc(a.username || "")}" ${a.id ? "readonly" : "required"} pattern="[a-zA-Z0-9_.\\-]{3,64}"></label>
    <label class="f"><span>F.I.Sh</span><input name="full_name" value="${esc(a.full_name || "")}"></label>
    <label class="f"><span>Rol</span><select name="role">${["superadmin", "admin", "auditor"].map((r) => `<option ${a.role === r ? "selected" : ""}>${r}</option>`).join("")}</select></label>
    <label class="f"><span>${a.id ? "Yangi parol (o'zgartirmaslik uchun bo'sh; o'rnatilsa 2FA o'chadi)" : "Parol (kamida 10 belgi, harf+raqam)"}</span><input name="password" type="password" autocomplete="new-password" ${a.id ? "" : "required"}></label>
    <label class="chk"><input type="checkbox" name="is_active" ${a.is_active ? "checked" : ""}> Faol</label>
    <div class="row end mt">${a.id ? `<button type="button" class="danger" data-act="admindel" data-id="${a.id}">O'chirish</button><span class="spacer"></span>` : ""}<button type="button" data-act="close">Bekor</button><button class="primary">Saqlash</button></div></form>`);
};
ACT.adminsave = (f) => run(async () => {
  const fd = Object.fromEntries(new FormData(f)); const body = { ...fd, is_active: "is_active" in fd, password: fd.password || null };
  f.dataset.id ? await api("PUT", "/api/admin/admins/" + f.dataset.id, body) : await api("POST", "/api/admin/admins", body);
  closeModal(); toast("Saqlandi"); route();
});
ACT.admindel = (el) => run(async () => { await api("DELETE", "/api/admin/admins/" + el.dataset.id); closeModal(); toast("O'chirildi"); route(); });

/* ================================================= PROFIL */
ROUTES.profile = async (v) => {
  window.onResize = null;
  S.me = await api("GET", "/api/admin/auth/me");
  v.innerHTML = head("Profil", esc(S.me.username) + " · " + S.me.role) + `<div class="grid g2">
    <form class="card" data-submit="chpw"><h2>Parolni o'zgartirish</h2>
      <label class="f"><span>Joriy parol</span><input type="password" name="old_password" autocomplete="current-password" required></label>
      <label class="f"><span>Yangi parol</span><input type="password" name="new_password" autocomplete="new-password" required minlength="10"></label>
      <div class="row end"><button class="primary">O'zgartirish</button></div></form>
    <div class="card"><h2>Ikki bosqichli himoya (2FA)</h2>
      ${S.me.totp_enabled ? `<div class="alert good">2FA yoqilgan.</div><form data-submit="tfaoff" class="row"><input type="password" name="password" placeholder="Parolingiz" required><button class="danger">O'chirish</button></form>`
        : `<p class="small">Google Authenticator yoki shunga o'xshash ilova orqali har kirishda 6 xonali kod so'raladi.</p><button class="primary" data-act="tfasetup">Yoqish</button><div id="tfa" class="mt"></div>`}</div></div>`;
};
ACT.chpw = (f) => run(async () => { await api("POST", "/api/admin/auth/password", Object.fromEntries(new FormData(f))); toast("Parol o'zgartirildi"); f.reset(); });
ACT.tfasetup = () => run(async () => {
  const r = await api("POST", "/api/admin/auth/2fa/setup");
  $("#tfa").innerHTML = `<p class="small">Ilovaga quyidagi kalitni qo'lda kiriting (yoki URI dan foydalaning):</p><div class="keybox" id="tfakey">${esc(r.secret)}</div>
    <p class="mono small muted" style="overflow-wrap:anywhere">${esc(r.uri)}</p>
    <form data-submit="tfaon" class="row"><input type="hidden" name="secret" value="${esc(r.secret)}"><input name="code" placeholder="Ilovadagi 6 xonali kod" inputmode="numeric" maxlength="6" required><input type="password" name="password" placeholder="Parolingiz" required><button class="primary">Tasdiqlash</button></form>`;
});
ACT.tfaon = (f) => run(async () => { await api("POST", "/api/admin/auth/2fa/enable", Object.fromEntries(new FormData(f))); toast("2FA yoqildi"); route(); });
ACT.tfaoff = (f) => run(async () => { await api("POST", "/api/admin/auth/2fa/disable", Object.fromEntries(new FormData(f))); toast("2FA o'chirildi"); route(); });

/* ------------------------------------------------ start */
async function boot() {
  layout();
  if (!location.hash) location.hash = "#/";
  route();
}
(async () => {
  await loadBrand();
  if (S.brand.org_name) document.title = `${S.brand.org_short || S.brand.org_name} — HEMIS Gateway`;
  try { S.me = await api("GET", "/api/admin/auth/me"); boot(); } catch (_) { renderLogin(); }
})();

/* ================================================= XAVFSIZLIK */
let SECTAB = "overview";
const AREA_L = { all: "Hammasi", gateway: "Gateway (API)", admin: "Admin panel", docs: "Docs" };
ACT.cresume = (el) => run(async () => { await api("POST", `/api/admin/security/clients/${el.dataset.id}/resume`); toast("Mijoz qayta yoqildi"); route(); });
ACT.csuspend = (el) => modal(`<form data-submit="csuspendgo" data-id="${el.dataset.id}"><h2>Mijozni vaqtincha to'xtatish</h2><p class="small">Kalit o'chirilmaydi, muddat tugagach avtomatik qayta ishlaydi.</p>
  <label class="f"><span>Muddat (daqiqa)</span><input name="minutes" type="number" min="1" value="60" required></label>
  <label class="f"><span>Sabab</span><input name="reason" value="qo'lda to'xtatildi"></label>
  <div class="row end"><button type="button" data-act="close">Bekor</button><button class="primary">To'xtatish</button></div></form>`);
ACT.csuspendgo = (f) => run(async () => { const fd = Object.fromEntries(new FormData(f)); await api("POST", `/api/admin/security/clients/${f.dataset.id}/suspend`, { minutes: +fd.minutes, reason: fd.reason }); closeModal(); toast("To'xtatildi"); route(); });

function ruleForm(ip = "", action = "block") {
  return `<form data-submit="ruleadd"><h2>${action === "block" ? "IP ni bloklash" : "Ishonchli IP qo'shish"}</h2>
    <div class="grid g2"><label class="f"><span>IP yoki tarmoq (CIDR)</span><input name="cidr" value="${esc(ip)}" placeholder="91.204.12.77 yoki 10.0.0.0/24" required></label>
    <label class="f"><span>Turi</span><select name="action"><option value="block" ${action === "block" ? "selected" : ""}>Bloklash (qora ro'yxat)</option><option value="allow" ${action === "allow" ? "selected" : ""}>Ishonchli (oq ro'yxat — avtomatik ban qilinmaydi)</option></select></label>
    <label class="f"><span>Qayerga</span><select name="area">${Object.entries(AREA_L).map(([k, l]) => `<option value="${k}">${l}</option>`).join("")}</select></label>
    <label class="f"><span>Muddat</span><select name="minutes"><option value="60">1 soat</option><option value="1440" selected>1 kun</option><option value="10080">7 kun</option><option value="43200">30 kun</option><option value="0">Doimiy</option></select></label></div>
    <label class="f"><span>Sabab</span><input name="reason" placeholder="masalan: skaner, brute-force"></label>
    <div class="row end"><button type="button" data-act="close">Bekor</button><button class="primary">Saqlash</button></div></form>`;
}
ACT.ipblock = (el) => modal(ruleForm(el.dataset.ip, "block"));
ACT.ruleadd = (f) => run(async () => { const fd = Object.fromEntries(new FormData(f)); await api("POST", "/api/admin/security/rules", { ...fd, minutes: +fd.minutes }); closeModal(); toast(fd.action === "block" ? "Bloklandi" : "Qo'shildi"); if (location.hash.startsWith("#/security")) { if (SECTAB !== "overview") SECTAB = fd.action; route(); } });
ACT.ruledel = (el) => run(async () => { await api("DELETE", "/api/admin/security/rules/" + el.dataset.id); toast("O'chirildi"); route(); });
ACT.sectab = (el) => { SECTAB = el.dataset.t; route(); };

ROUTES.security = async (v) => {
  window.onResize = null;
  const T = [["overview", "Umumiy"], ["allow", "Oq ro'yxat"], ["block", "Qora ro'yxat"], ["events", "Hodisalar"], ["settings", "Avtomatik himoya"], ["telegram", "Telegram"]];
  v.innerHTML = head("Xavfsizlik", "IP bloklash, avtomatik himoya, kalit o'g'irlanishi va ogohlantirishlar",
    can("superadmin", "admin") ? `<button data-act="ipallow">+ Ishonchli IP</button><button class="primary" data-act="ipblock" data-ip="">+ IP bloklash</button>` : "") +
    `<div class="tabs">${T.map(([k, l]) => `<button class="${k === SECTAB ? "on" : ""}" data-act="sectab" data-t="${k}">${l}</button>`).join("")}</div><div id="sectab"></div>`;
  const t = $("#sectab");
  if (SECTAB === "overview") {
    const o = await api("GET", "/api/admin/security/overview");
    const ev = await api("GET", "/api/admin/security/events?limit=8");
    t.innerHTML = `<div class="grid g4">${tile("Faol bloklar", fmt(o.active_blocks), `${o.auto_blocks} tasi avtomatik`)}${tile("Ishonchli qoidalar", fmt(o.allow_rules), "oq ro'yxat")}${tile("To'xtatilgan mijozlar", fmt(o.suspended_clients), "kalit o'g'irlanishi gumoni")}${tile("Hodisalar (24 soat)", fmt(Object.values(o.events_24h).reduce((a, b) => a + b, 0)), "Sizning IP: " + esc(o.my_ip || "—"))}</div>
      <div class="grid g2 mt"><div class="card"><h2>Oxirgi 1 soatda eng ko'p rad etilgan IP lar</h2>${o.top_denied_ips_1h.length ? `<table>${o.top_denied_ips_1h.map((x) => `<tr><td class="mono"><a href="#/logs?ip=${encodeURIComponent(x.ip)}">${esc(x.ip)}</a></td><td class="num"><span class="pill serious">${fmt(x.count)}</span></td><td class="num">${x.blocked ? '<span class="pill bad">bloklangan</span>' : can("superadmin", "admin") ? `<button class="sm danger" data-act="ipblock" data-ip="${esc(x.ip)}">Bloklash</button>` : ""}</td></tr>`).join("")}</table>` : '<div class="empty">Shubhali faollik yo\'q</div>'}</div>
      <div class="card"><h2>Oxirgi hodisalar</h2>${evTable(ev, true)}</div></div>`;
  } else if (SECTAB === "allow" || SECTAB === "block") {
    await listTab(t, SECTAB);
  } else if (SECTAB === "events") {
    const ev = await api("GET", "/api/admin/security/events?limit=200");
    t.innerHTML = `<div class="card">${evTable(ev, false)}<p class="muted small">Jami: ${fmt(ev.total)}</p></div>`;
  } else if (SECTAB === "settings") {
    const st = await api("GET", "/api/admin/security/settings");
    const ro = can("superadmin") ? "" : "disabled";
    const num = (k, l, h) => `<label class="f"><span>${l}</span><input name="${k}" type="number" value="${esc(st[k])}" ${ro}><span class="muted small">${h ? h + " · " : ""}standart: ${esc(st.defaults[k])}</span></label>`;
    t.innerHTML = `<form class="card" data-submit="secsave"><h2>Avtomatik IP ban</h2>
      <label class="chk"><input type="checkbox" name="auto_ban_enabled" ${st.auto_ban_enabled === "1" ? "checked" : ""} ${ro}> Yoqilgan</label>
      <div class="grid g3 mt">${num("abuse_threshold", "Rad etilgan so'rovlar chegarasi", "401/403/404/400 javoblar soni")}${num("abuse_window", "Oyna (soniya)", "shu vaqt ichida")}
        <label class="f"><span>Ban muddatlari (soniya, bosqichma-bosqich)</span><input name="ban_steps" value="${esc(st.ban_steps)}" ${ro}><span class="muted small">1-marta, 2-marta, keyingilari · standart: ${st.defaults.ban_steps}</span></label></div>
      <p class="muted small">Xato login urinishi 3 baravar og'ir hisoblanadi. Ishonchli IP lar ban qilinmaydi.</p>
      <h2 class="mt">Kalit o'g'irlanishi</h2><div class="grid g3">${num("client_max_ips", "Turli IP lar chegarasi (0 = o'chiq)", "mijozda alohida sozlanmagan bo'lsa")}${num("client_ips_window", "Oyna (soniya)")}${num("suspend_seconds", "To'xtatish muddati (soniya)")}</div>
      <h2 class="mt">Login himoyasi va ogohlantirish</h2><div class="grid g3">${num("captcha_after", "Nechta xato logindan keyin captcha", "admin va docs sahifalari")}${num("alert_5xx_threshold", "5 daqiqada 5xx xatolar (ogohlantirish)")}</div>
      ${ro ? "" : '<div class="row end"><button class="primary">Saqlash</button></div>'}</form>`;
  } else if (SECTAB === "telegram") {
    const st = await api("GET", "/api/admin/security/settings");
    const ev = await api("GET", "/api/admin/security/events?limit=1");
    const on = new Set(st.alert_events.split(","));
    const ro = can("superadmin") ? "" : "disabled";
    const evs = ["ip_banned", "client_suspended", "admin_lock", "admin_new_ip", "upstream_auth", "errors_5xx", "login_bruteforce", "spec_changed"];
    t.innerHTML = `<form class="card" data-submit="tgsave"><h2>Telegram ogohlantirishlari</h2>
      <ol class="small" style="padding-left:18px;line-height:1.7;margin-top:0"><li>Telegramda <span class="mono">@BotFather</span> → <span class="mono">/newbot</span> orqali bot yarating va tokenni oling.</li><li>Botni guruhga qo'shing (yoki botga o'zingiz yozing).</li><li>Chat ID: guruh uchun odatda <span class="mono">-100…</span> bilan boshlanadi (<span class="mono">@userinfobot</span> yoki <span class="mono">getUpdates</span> orqali bilish mumkin).</li></ol>
      <div class="grid g2"><label class="f"><span>Bot token ${st.telegram_bot_token_set ? '<span class="pill good">o\'rnatilgan</span>' : ""}</span><input name="telegram_bot_token" type="password" autocomplete="off" placeholder="o'zgartirmaslik uchun bo'sh" ${ro}></label>
      <label class="f"><span>Chat ID</span><input name="telegram_chat_id" value="${esc(st.telegram_chat_id)}" placeholder="-1001234567890" ${ro}></label></div>
      <label class="chk"><input type="checkbox" name="alerts_enabled" ${st.alerts_enabled === "1" ? "checked" : ""} ${ro}> Ogohlantirishlar yoqilgan</label>
      <h3 class="mt">Qaysi hodisalar yuborilsin</h3><div>${evs.map((e) => `<label class="chk"><input type="checkbox" name="ev_${e}" ${on.has(e) ? "checked" : ""} ${ro}> ${esc(ev.labels[e] || e)}</label>`).join("<br>")}</div>
      <p class="muted small">Bir xil hodisa 10 daqiqada bir martadan ko'p yuborilmaydi.</p>
      ${ro ? "" : '<div class="row end"><button type="button" data-act="tgtest">Test xabar yuborish</button><button class="primary">Saqlash</button></div>'}<div id="tgres" class="mt"></div></form>`;
  }
};
ACT.ipallow = () => modal(ruleForm("", "allow"));
function evTable(ev, short) {
  const sevPill = (s) => `<span class="pill ${s === "high" ? "bad" : s === "warn" ? "warn" : "plain"}">${esc(s === "high" ? "yuqori" : s === "warn" ? "o'rta" : "info")}</span>`;
  if (!ev.items.length) return '<div class="empty">Hodisalar yo\'q</div>';
  return `<div class="table-wrap"><table><tr><th>Vaqt</th><th>Hodisa</th>${short ? "" : "<th>Daraja</th>"}<th>Tafsilot</th>${short ? "" : "<th>IP</th>"}</tr>${ev.items.map((x) => `<tr><td class="small" style="white-space:nowrap">${dt(x.ts)}</td><td>${short ? sevPill(x.severity) + " " : ""}${esc(ev.labels[x.type] || x.type)}</td>${short ? "" : `<td>${sevPill(x.severity)}</td>`}<td class="small">${esc(x.message)}</td>${short ? "" : `<td class="mono small">${esc(x.ip)}</td>`}</tr>`).join("")}</table></div>`;
}
ACT.secsave = (f) => run(async () => {
  const fd = Object.fromEntries(new FormData(f)); fd.auto_ban_enabled = "auto_ban_enabled" in fd ? "1" : "0";
  await api("PUT", "/api/admin/security/settings", fd); toast("Saqlandi");
});
ACT.tgsave = (f) => run(async () => {
  const fd = Object.fromEntries(new FormData(f));
  const events = Object.keys(fd).filter((k) => k.startsWith("ev_")).map((k) => k.slice(3));
  await api("PUT", "/api/admin/security/settings", { telegram_bot_token: fd.telegram_bot_token || null, telegram_chat_id: fd.telegram_chat_id, alerts_enabled: "alerts_enabled" in fd ? "1" : "0", alert_events: events.join(",") });
  toast("Saqlandi"); route();
});
ACT.tgtest = () => run(async () => {
  const f = $("form[data-submit=tgsave]"); const fd = Object.fromEntries(new FormData(f));
  const r = await api("POST", "/api/admin/security/telegram-test", { telegram_bot_token: fd.telegram_bot_token || null, telegram_chat_id: fd.telegram_chat_id || null });
  $("#tgres").innerHTML = r.ok ? '<div class="alert good">Xabar yuborildi — Telegramni tekshiring.</div>' : `<div class="alert bad">Yuborilmadi: ${esc(r.error)}</div>`;
});

/* ---------- Oq / qora ro'yxat ---------- */
const LST = { rows: [], kind: "block", q: "", f: "active", sel: new Set() };
async function listTab(t, kind) {
  LST.kind = kind; LST.sel = new Set();
  LST.rows = (await api("GET", "/api/admin/security/rules")).filter((r) => r.action === kind);
  const ed = can("superadmin", "admin");
  const base = `/api/admin/security/lists/${kind}`;
  t.innerHTML = `<div class="card">
    <div class="row" style="margin-bottom:12px">
      <input placeholder="IP yoki sabab bo'yicha qidirish…" data-inp="lq" value="${esc(LST.q)}" style="flex:1;min-width:200px">
      <select data-chg="lf"><option value="active" ${LST.f === "active" ? "selected" : ""}>Faollari</option><option value="all" ${LST.f === "all" ? "selected" : ""}>Hammasi</option><option value="expired" ${LST.f === "expired" ? "selected" : ""}>Muddati tugaganlar</option>${kind === "block" ? `<option value="manual" ${LST.f === "manual" ? "selected" : ""}>Faqat qo'lda</option><option value="auto" ${LST.f === "auto" ? "selected" : ""}>Faqat avtomatik</option>` : ""}</select>
      <span class="spacer"></span>
      <a class="btn" href="${base}/export?include_expired=${LST.f === "all" || LST.f === "expired" ? 1 : 0}" download>Excel eksport</a>
      ${ed ? `<a class="btn" href="${base}/template" download>Shablon</a><button data-act="limport">Excel import</button><button class="primary" data-act="${kind === "block" ? "ipblock" : "ipallow"}" data-ip="">+ Qo'shish</button>` : ""}
    </div>
    <p class="muted small" style="margin-top:-4px">${kind === "allow" ? "Oq ro'yxatdagi IP lar hech qachon bloklanmaydi va avtomatik ban qilinmaydi (bloklardan ustun). OTM tarmog'i, server va hamkor tizimlar IP larini qo'shing." : "Qora ro'yxatdagi IP lar tanlangan bo'limga kira olmaydi. Avtomatik banlar ham shu yerda ko'rinadi."}</p>
    <div id="lsel" class="row" style="display:none;margin-bottom:8px"><span id="lselc" class="small"></span><button class="sm danger" data-act="lbulkdel">Tanlanganlarni ${kind === "block" ? "blokdan chiqarish" : "o'chirish"}</button></div>
    <div class="table-wrap"><table id="ltable"></table></div><div id="lcount" class="muted small mt"></div></div>`;
  drawList();
}
function listFiltered() {
  const q = LST.q.toLowerCase();
  return LST.rows.filter((r) => (!q || r.cidr.toLowerCase().includes(q) || (r.reason || "").toLowerCase().includes(q))
    && (LST.f === "all" || (LST.f === "active" && r.active) || (LST.f === "expired" && !r.active) || (LST.f === "manual" && !r.auto && r.active) || (LST.f === "auto" && r.auto && r.active)));
}
function drawList() {
  const rows = listFiltered(), ed = can("superadmin", "admin"), kind = LST.kind;
  $("#ltable").innerHTML = `<tr>${ed ? `<th style="width:28px"><input type="checkbox" data-chg="lall" aria-label="hammasi"></th>` : ""}<th>IP / tarmoq</th>${kind === "block" ? "<th>Turi</th>" : ""}<th>Qayerga</th><th>Sabab</th><th>Muddat</th><th>Kim</th><th>Qo'shilgan</th><th></th></tr>` +
    (rows.map((r) => `<tr style="${r.active ? "" : "opacity:.5"}">${ed ? `<td><input type="checkbox" data-chg="lone" value="${r.id}" ${LST.sel.has(r.id) ? "checked" : ""}></td>` : ""}
      <td class="mono">${esc(r.cidr)}</td>${kind === "block" ? `<td><span class="pill ${r.auto ? "serious" : "bad"}">${r.auto ? "avtomatik" : "qo'lda"}</span></td>` : ""}
      <td>${AREA_L[r.area] || r.area}</td><td class="small">${esc(r.reason)}</td>
      <td class="small">${r.expires_at ? (r.active ? dt(r.expires_at) + " gacha" : "tugagan") : "doimiy"}</td><td class="small">${esc(r.created_by)}</td><td class="small">${dt(r.created_at)}</td>
      <td class="num">${ed ? `<button class="sm" data-act="ruledel" data-id="${r.id}">${kind === "block" ? "Chiqarish" : "O'chirish"}</button>` : ""}</td></tr>`).join("") || `<tr><td colspan=9 class="empty">${LST.rows.length ? "Filtr bo'yicha topilmadi" : "Ro'yxat bo'sh"}</td></tr>`);
  $("#lcount").textContent = `Ko'rsatilgan: ${rows.length} / ${LST.rows.length}`;
  const n = LST.sel.size; $("#lsel").style.display = n ? "flex" : "none"; $("#lselc").textContent = `${n} ta tanlandi`;
}
CHG.lq = (el) => { LST.q = el.value; drawList(); };
CHG.lf = (el) => { LST.f = el.value; route(); };
CHG.lone = (el) => { el.checked ? LST.sel.add(+el.value) : LST.sel.delete(+el.value); drawList(); };
CHG.lall = (el) => { listFiltered().forEach((r) => (el.checked ? LST.sel.add(r.id) : LST.sel.delete(r.id))); drawList(); };
ACT.lbulkdel = () => modal(`<h2>${LST.sel.size} ta yozuvni ${LST.kind === "block" ? "blokdan chiqarish" : "o'chirish"}</h2><p>Bu amal audit jurnaliga yoziladi.</p><div class="row end"><button data-act="close">Bekor</button><button class="primary" data-act="lbulkgo">Tasdiqlash</button></div>`);
ACT.lbulkgo = () => run(async () => { const r = await api("POST", `/api/admin/security/lists/${LST.kind}/bulk-delete`, { ids: [...LST.sel] }); closeModal(); toast(`${r.deleted} ta o'chirildi`); route(); });

ACT.limport = () => {
  const k = LST.kind;
  modal(`<form data-submit="limportgo"><h2>${k === "block" ? "Qora" : "Oq"} ro'yxatga Excel import</h2>
    <p class="small">Fayl ustunlari: <b>IP / tarmoq</b> (majburiy), Qayerga, Tugash vaqti, Sabab. <a href="/api/admin/security/lists/${k}/template" download>Shablonni yuklab olish</a></p>
    <label class="f"><span>Excel fayl (.xlsx)</span><input type="file" name="file" accept=".xlsx" required data-chg="lfile"></label>
    <label class="chk"><input type="radio" name="mode" value="merge" checked data-chg="lfile"> Qo'shish — mavjudlari yangilanadi</label><br>
    <label class="chk"><input type="radio" name="mode" value="replace" data-chg="lfile"> Almashtirish — qo'lda kiritilganlar fayldagilar bilan almashtiriladi${k === "block" ? " (avtomatik banlar saqlanadi)" : ""}</label>
    <div id="limpres" class="mt"></div>
    <div class="row end mt"><button type="button" data-act="close">Bekor</button><button type="button" data-act="limportcheck">Tekshirish</button><button class="primary" id="limpgo" disabled>Import qilish</button></div></form>`, true);
};
CHG.lfile = () => { $("#limpgo").disabled = true; $("#limpres").innerHTML = ""; };
async function sendImport(dry) {
  const f = $("form[data-submit=limportgo]"); const fd = new FormData(f);
  if (!fd.get("file") || !fd.get("file").size) throw new Error("Faylni tanlang");
  fd.set("dry_run", dry ? "true" : "false");
  return api("POST", `/api/admin/security/lists/${LST.kind}/import`, fd, true);
}
function importReport(r) {
  const list = (arr, cls) => arr.length ? `<div class="table-wrap" style="max-height:220px;overflow:auto"><table><tr><th>Qator</th><th>Qiymat</th><th>Izoh</th></tr>${arr.map((e) => `<tr><td class="num">${e.row}</td><td class="mono">${esc(e.value)}</td><td class="small">${esc(e.error)}</td></tr>`).join("")}</table></div>` : "";
  return `<div class="alert ${r.error_count ? "" : "good"}"><b>${r.dry_run ? "Tekshiruv natijasi" : "Import bajarildi"}:</b> ${r.rows} ta qator — <b>+${r.added}</b> yangi, <b>${r.updated}</b> ${r.dry_run ? "yangilanadi" : "yangilandi"}${r.mode === "replace" ? `, <b>${r.removed}</b> ${r.dry_run ? "o'chiriladi" : "o'chirildi"}` : ""}${r.error_count ? `, <b>${r.error_count}</b> ta xato qator o'tkazib yuboriladi` : ""}${r.warning_count ? `, ${r.warning_count} ta ogohlantirish` : ""}.</div>
    ${r.error_count ? `<h3>Xatolar</h3>${list(r.errors)}` : ""}${r.warning_count ? `<h3 class="mt">Ogohlantirishlar</h3>${list(r.warnings)}` : ""}`;
}
ACT.limportcheck = () => run(async () => {
  const r = await sendImport(true);
  $("#limpres").innerHTML = importReport(r);
  $("#limpgo").disabled = !(r.added || r.updated || r.removed);
});
ACT.limportgo = () => run(async () => {
  const r = await sendImport(false);
  toast(`Import: +${r.added} yangi, ${r.updated} yangilandi${r.removed ? ", " + r.removed + " o'chirildi" : ""}`);
  route(); setTimeout(() => { modal(`<h2>Import natijasi</h2>${importReport(r)}<div class="row end mt"><button class="primary" data-act="close">Yopish</button></div>`, true); }, 300);
});

/* ---------- HEMIS docs (docs.json) yangilash ---------- */
const SPEC = { versions: [] };
function specSourceForm(preset) {
  const vs = SPEC.versions;
  return `<div class="row" style="gap:16px;margin-bottom:10px">
      <label class="chk"><input type="radio" name="src" value="file" ${!preset ? "checked" : ""} data-chg="specsrc"> Fayl (.json)</label>
      <label class="chk"><input type="radio" name="src" value="url" data-chg="specsrc"> URL</label>
      <label class="chk"><input type="radio" name="src" value="version" ${preset ? "checked" : ""} data-chg="specsrc"> Arxivdagi versiya</label></div>
    <div data-s="file" style="display:${preset ? "none" : "block"}"><input type="file" name="file" accept=".json,application/json" data-chg="specreset"></div>
    <div data-s="url" style="display:none"><input name="url" style="width:100%" placeholder="https://student.otm.uz/rest/docs.json" value="${esc(SPEC.url || "")}" data-inp="specreset"></div>
    <div data-s="version" style="display:${preset ? "block" : "none"}"><select name="version" style="width:100%" data-chg="specreset">${vs.map((v) => `<option value="${esc(v.name)}" ${v.name === preset ? "selected" : ""}>${dt(v.saved_at)} · v${esc(v.version || "?")} · ${v.operations} endpoint${v.current ? " (joriy)" : ""}</option>`).join("")}</select></div>`;
}
async function loadVersions() { const r = await api("GET", "/api/admin/spec/versions"); SPEC.versions = r.versions; SPEC.url = r.spec_url; return r; }
ACT.specopen = (el) => run(async () => {
  await loadVersions();
  modal(`<form data-submit="specapply"><h2>HEMIS API hujjatini yangilash</h2>
    <p class="small muted" style="margin-top:-4px">Yangi docs.json yuklang — avval nima o'zgarishi va qaysi mijozlarga ta'sir qilishi ko'rsatiladi, so'ng siz tasdiqlaysiz. Mavjud ruxsatlar va sozlamalar saqlanadi, yangi endpointlar hech kimga yoqilmagan holda qo'shiladi, olib tashlanganlari o'chirilmaydi (faqat yopiladi).</p>
    ${specSourceForm(el && el.dataset ? el.dataset.v : "")}
    <div id="specres" class="mt"></div>
    <div class="row end mt"><button type="button" data-act="close">Bekor</button><button type="button" data-act="specpreview">Farqni ko'rish</button><button class="primary" id="specgo" disabled>Qo'llash</button></div></form>`, true);
});
CHG.specsrc = (el) => { $$("#modal [data-s]").forEach((d) => (d.style.display = d.dataset.s === el.value ? "block" : "none")); CHG.specreset(); };
CHG.specreset = () => { const b = $("#specgo"); if (b) b.disabled = true; const r = $("#specres"); if (r) r.innerHTML = ""; };
function specForm() {
  const f = $("form[data-submit=specapply]"), src = new FormData(f).get("src"), fd = new FormData();
  if (src === "file") { const file = f.querySelector("[name=file]").files[0]; if (!file) throw new Error("Faylni tanlang"); fd.append("file", file); }
  if (src === "url") { const u = f.querySelector("[name=url]").value.trim(); if (!u) throw new Error("URL kiriting"); fd.append("url", u); }
  if (src === "version") fd.append("version", f.querySelector("[name=version]").value);
  return fd;
}
const epList = (arr, fn) => arr.length ? `<div class="table-wrap" style="max-height:200px;overflow:auto"><table>${arr.map(fn).join("")}</table></div>` : '<div class="muted small">—</div>';
ACT.specpreview = () => run(async () => {
  $("#specres").innerHTML = '<div class="muted">Tahlil qilinmoqda…</div>';
  const d = await api("POST", "/api/admin/spec/preview", specForm(), true);
  const high = d.impacts.filter((i) => i.level === "high").length;
  const lvl = { high: "bad", warn: "warn", info: "plain" };
  $("#specres").innerHTML = `
    ${d.same_as_current ? '<div class="alert good">Bu fayl joriy hujjat bilan bir xil.</div>' : ""}
    ${d.large_removal ? `<div class="alert bad"><b>Diqqat:</b> ${d.removed.length} ta endpoint olib tashlanadi. Fayl noto'g'ri (boshqa tizim yoki eski versiya) bo'lishi mumkin. <label class="chk"><input type="checkbox" name="confirm_large"> Baribir qo'llash</label></div>` : ""}
    <div class="grid g4">${tile("Yangi hujjat", fmt(d.info.operations), `v${esc(d.info.version || "?")} · ${esc(d.source)}`)}${tile("Qo'shiladi", "+" + fmt(d.added.length), "hech kimga yoqilmaydi")}${tile("Olib tashlanadi", fmt(d.removed.length), "410 qaytaradi")}${tile("O'zgargan", fmt(d.changed.length), "filtrlar yoki tavsif")}</div>
    ${d.no_changes ? '<div class="alert good mt">Endpoint va filtrlar tuzilmasida o\'zgarish yo\'q.</div>' : ""}
    ${d.impacts.length ? `<h3 class="mt">Mijozlarga ta'siri ${high ? `<span class="pill bad">${high} ta jiddiy</span>` : ""}</h3>${epList(d.impacts, (i) => `<tr><td><span class="pill ${lvl[i.level]}">${i.level === "high" ? "jiddiy" : i.level === "warn" ? "diqqat" : "info"}</span></td><td><a href="#/clients/${i.client_id}/perms">${esc(i.client)}</a></td><td class="mono small">${esc(i.endpoint)}</td><td class="small">${esc(i.message)}</td></tr>`)}` : ""}
    ${d.added.length ? `<details class="mt" open><summary><b>Yangi endpointlar (${d.added.length})</b></summary>${epList(d.added, (e) => `<tr><td><span class="m ${e.method}">${e.method}</span></td><td class="mono small">${esc(e.path)}</td><td class="small">${esc(e.summary)}${e.restored ? ' <span class="pill plain">qayta qo\'shildi</span>' : ""}</td></tr>`)}</details>` : ""}
    ${d.removed.length ? `<details class="mt" open><summary><b>Olib tashlanadigan endpointlar (${d.removed.length})</b></summary>${epList(d.removed, (e) => `<tr><td><span class="m ${e.method}">${e.method}</span></td><td class="mono small">${esc(e.path)}</td><td class="small">${e.clients.length ? `<span class="pill bad">${e.clients.length} mijoz</span> ${esc(e.clients.join(", "))}` : esc(e.summary)}</td></tr>`)}</details>` : ""}
    ${d.changed.length ? `<details class="mt"><summary><b>O'zgargan endpointlar (${d.changed.length})</b></summary>${epList(d.changed, (e) => `<tr><td><span class="m ${e.method}">${e.method}</span></td><td class="mono small">${esc(e.path)}</td><td class="small">${e.params_added.length ? `<span style="color:var(--good-text)">+ ${esc(e.params_added.join(", "))}</span> ` : ""}${e.params_removed.length ? `<span style="color:var(--critical)">− ${esc(e.params_removed.join(", "))}</span> ` : ""}${e.summary_changed ? '<span class="muted">tavsif</span> ' : ""}${e.body_changed ? '<span class="muted">so\'rov tanasi</span>' : ""}</td></tr>`)}</details>` : ""}`;
  $("#specgo").disabled = d.same_as_current;
});
ACT.specapply = () => run(async () => {
  const fd = specForm(); const c = $("#modal [name=confirm_large]"); if (c && c.checked) fd.append("confirm_large", "true");
  const r = await api("POST", "/api/admin/spec/apply", fd, true);
  closeModal(); toast(`Hujjat yangilandi: +${r.added} yangi, ${r.removed} olib tashlandi${r.restored ? ", " + r.restored + " qaytdi" : ""}`);
  S.endpoints = null; route();
});
ACT.specversions = () => run(async () => {
  const r = await loadVersions();
  modal(`<h2>HEMIS docs versiyalari</h2>
    <p class="small muted" style="margin-top:-4px">Har bir qo'llangan docs.json arxivlanadi. Istalgan versiyaga farqni ko'rib, qaytish mumkin.</p>
    <div class="table-wrap" style="max-height:260px;overflow:auto"><table><tr><th>Saqlangan</th><th>Versiya</th><th class="num">Endpoint</th><th class="num">Hajm</th><th></th></tr>${r.versions.map((v) => `<tr><td class="small">${dt(v.saved_at)}</td><td>v${esc(v.version || "?")} ${v.current ? '<span class="pill good">joriy</span>' : ""}</td><td class="num">${v.operations}</td><td class="num">${bytes(v.size)}</td>
      <td class="num"><a class="btn sm" href="/api/admin/spec/versions/${encodeURIComponent(v.name)}/download" download>Yuklab olish</a> ${v.current || !can("superadmin") ? "" : `<button class="sm" data-act="specopen" data-v="${esc(v.name)}">Qaytish…</button>`}</td></tr>`).join("") || '<tr><td colspan=5 class="empty">Arxiv bo\'sh</td></tr>'}</table></div>
    <div class="row end mt"><button data-act="close">Yopish</button></div>`, true);
});

/* ---------- Avtomatik sinxronlash ---------- */
const SYNC_STATUS = { applied: ["good", "qo'llandi"], same: ["good", "bir xil"], pending: ["warn", "tasdiq kutilmoqda"], notified: ["warn", "yangi versiya bor"], error: ["bad", "xato"] };
async function syncBar() {
  const el = $("#syncbar"); if (!el) return;
  let c; try { c = await api("GET", "/api/admin/spec/sync"); } catch (_) { return; }
  const st = SYNC_STATUS[c.last_status];
  const pending = c.last_status === "pending" || c.last_status === "notified";
  el.innerHTML = `<div class="alert ${c.mode === "off" ? "" : st && st[0] === "bad" ? "bad" : pending ? "" : "good"} row" style="margin-bottom:14px">
    <span><b>HEMIS bilan avto-sinxronlash:</b> ${esc(c.modes[c.mode])}${c.mode !== "off" ? `, har ${c.hours} soatda` : ""}.
    ${c.last_check ? `Oxirgi: ${dt(c.last_check)} ${st ? `<span class="pill ${st[0]}">${st[1]}</span>` : ""} <span class="small">${esc(c.last_result)}</span>` : '<span class="small">Hali tekshirilmagan.</span>'}</span>
    <span class="spacer"></span>${pending && can("superadmin") && c.url ? `<button class="sm primary" data-act="specopenurl" data-url="${esc(c.url)}">Ko'rib chiqish</button>` : ""}${can("superadmin") ? '<button class="sm" data-act="syncnow">Hozir sinxronlash</button>' : ""}</div>`;
}
ACT.specopenurl = (el) => run(async () => {
  await ACT.specopen({ dataset: {} });
  const r = $('#modal input[name=src][value=url]'); r.checked = true; CHG.specsrc(r);
  $('#modal [name=url]').value = el.dataset.url;
  await ACT.specpreview();
});
ACT.syncnow = () => run(async () => {
  toast("HEMIS bilan sinxronlanmoqda…");
  const r = await api("POST", "/api/admin/spec/check-now");
  toast(r.message, !r.ok); S.endpoints = null;
  if (location.hash.startsWith("#/endpoints")) route();
});
ACT.syncopen = () => run(async () => {
  const c = await api("GET", "/api/admin/spec/sync"); const ro = can("superadmin") ? "" : "disabled";
  const desc = { off: "Tizim HEMIS docs ni tekshirmaydi.", notify: "O'zgarish topilsa faqat Hodisalar va Telegramga xabar keladi, siz qo'lda qo'llaysiz.",
    safe: "Mijozlarga jiddiy ta'sir qilmaydigan o'zgarishlar (yangi endpoint/filtr, tavsif, hech kim ishlatmayotgan endpointning olib tashlanishi) avtomatik qo'llanadi. Ishlatilayotgan endpoint yo'qolsa yoki qulflangan filtr o'chsa — tasdiq so'raladi. (Tavsiya)",
    full: "Barcha o'zgarishlar avtomatik qo'llanadi va keyin xabar beriladi. Faqat endpointlarning 30% dan ko'pi yo'qolsa (noto'g'ri fayl ehtimoli) to'xtab, tasdiq so'raydi." };
  modal(`<form data-submit="syncsave"><h2>HEMIS bilan avtomatik sinxronlash</h2>
    <p class="small muted" style="margin-top:-4px">Tizim HEMIS docs.json ni o'zi yuklab oladi, farqni hisoblaydi va endpointlar, filtrlar hamda ruxsat qoidalarini yangi tuzilmaga moslaydi. Har bir versiya arxivlanadi — istalgan vaqtda qaytish mumkin.</p>
    <label class="f"><span>HEMIS docs.json manzili</span><div class="row"><input name="url" value="${esc(c.url)}" placeholder="bo'sh qoldirilsa avtomatik topiladi" style="flex:1" ${ro}>${ro ? "" : '<button type="button" data-act="syncdiscover">Avtomatik topish</button>'}</div></label>
    <div id="discres" class="small"></div>
    <label class="f"><span>HEMIS docs paroli ${c.password_set ? '<span class="pill good">o\'rnatilgan</span>' : '<span class="muted">(docs sahifasi parol so\'rasa)</span>'}</span><input name="password" type="password" autocomplete="off" placeholder="o'zgartirmaslik uchun bo'sh qoldiring" ${ro}></label>
    <h3 class="mt">Rejim</h3>
    ${Object.entries(c.modes).map(([k, l]) => `<label class="chk" style="display:flex;align-items:flex-start;margin:0 0 10px"><input type="radio" name="mode" value="${k}" ${c.mode === k ? "checked" : ""} ${ro} style="margin-top:4px"><span><b>${esc(l)}</b><br><span class="small muted">${desc[k]}</span></span></label>`).join("")}
    <div class="grid g2 mt"><label class="f"><span>Tekshirish davriyligi</span><select name="hours" ${ro}>${[1, 3, 6, 12, 24].map((h) => `<option value="${h}" ${c.hours === h ? "selected" : ""}>har ${h} soatda</option>`).join("")}</select></label>
    <label class="f"><span>«Barcha filtrlar» yoqilgan mijozlarga yangi filtrlar</span><select name="new_filters" ${ro}><option value="freeze" ${c.new_filters === "freeze" ? "selected" : ""}>Avtomatik berilmasin (tavsiya)</option><option value="allow" ${c.new_filters === "allow" ? "selected" : ""}>Avtomatik ruxsat berilsin</option></select></label></div>
    <p class="small muted">Qoidalar qanday moslanadi: HEMIS da o'chirilgan filtrlar mijozlarning ruxsat ro'yxatidan tozalanadi; yangi endpointlar hech kimga avtomatik ochilmaydi (doira filtrlari esa o'zi aniqlanadi); qulflangan filtr yo'qolsa — endpoint shu mijozga rad etiladi va sizga xabar beriladi.</p>
    <div class="row end mt"><button type="button" data-act="close">Yopish</button>${ro ? "" : '<button type="button" data-act="syncsavenow">Saqlash va hozir sinxronlash</button><button class="primary">Saqlash</button>'}</div></form>`, true);
});
const syncData = () => { const fd = Object.fromEntries(new FormData($("form[data-submit=syncsave]"))); return { url: fd.url, mode: fd.mode, hours: +fd.hours, new_filters: fd.new_filters, password: fd.password || null }; };
ACT.syncsave = () => run(async () => { await api("PUT", "/api/admin/spec/sync", syncData()); closeModal(); toast("Saqlandi"); syncBar(); });
ACT.syncsavenow = () => run(async () => { await api("PUT", "/api/admin/spec/sync", syncData()); closeModal(); await ACT.syncnow(); });
ACT.syncdiscover = () => run(async () => {
  $("#discres").textContent = "Qidirilmoqda…";
  const r = await api("POST", "/api/admin/spec/discover");
  if (r.found) { $("form[data-submit=syncsave] [name=url]").value = r.found; $("#discres").innerHTML = `<div class="alert good">Topildi: <span class="mono">${esc(r.found)}</span></div>`; }
  else $("#discres").innerHTML = `<div class="alert bad">Topilmadi. Tekshirilgan manzillar: ${r.tried.map((t) => `<div class="mono small">${esc(t.url)} — ${esc(t.result)}</div>`).join("")}HEMIS swagger sahifasidagi JSON havolasini qo'lda kiriting.</div>`;
});
