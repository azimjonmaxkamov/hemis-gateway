/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Azimjon Makhkamov */
"use strict";
(() => {
  const esc = window.Charts.esc, $ = (s) => document.querySelector(s);
  const base = location.origin + "/rest";
  $("#base").textContent = base + "/v1/data/...\n" + location.origin + "/fast/...   (Fast API)";
  $("#ex").textContent = `curl -H "X-Gateway-Key: $KEY" \\\n  "${base}/v1/data/student-stats?group_by=level"`;
  $("#kform").addEventListener("submit", async (e) => {
    e.preventDefault();
    const key = $("#key").value.trim();
    if (!key) return;
    $("#info").innerHTML = '<span class="muted">Tekshirilmoqda…</span>';
    try {
      const r = await fetch("/gateway/me", { headers: { "X-Gateway-Key": key } });
      const d = await r.json();
      if (!r.ok) { $("#info").innerHTML = `<div class="alert bad">${esc(d.error || "Xato")}</div>`; $("#eps").innerHTML = ""; return; }
      const x = d.data;
      $("#info").innerHTML = `<div class="alert good"><b>${esc(x.client)}</b> — ${x.endpoints.length} ta endpoint ochiq. Limit: ${x.rate_per_second || "∞"}/soniya, ${x.rate_per_minute || "∞"}/daqiqa, ${x.daily_quota || "∞"}/kun.${Object.keys(x.scope || {}).length ? "<br>Doira: " + Object.entries(x.scope).map(([k, v]) => `${esc(k)} = ${esc(v.join(", "))}`).join("; ") : ""}</div>`;
      $("#eps").innerHTML = `<div class="card"><h2>Ochiq endpointlar</h2><div class="table-wrap"><table><tr><th></th><th>Manzil</th><th>Ruxsat etilgan filtrlar</th><th>Qulflangan</th><th class="num">Max limit</th></tr>${x.endpoints.map((e) => `<tr><td><span class="m ${e.method}">${e.method}</span></td><td><div class="mono" style="overflow-wrap:anywhere">${esc(e.url)}</div><div class="muted small">${esc(e.summary)}</div></td><td>${e.allowed_filters.map((f) => `<span class="chip">${esc(f)}</span>`).join(" ") || '<span class="muted">—</span>'}</td><td>${Object.entries(e.locked_filters).map(([k, v]) => `<span class="chip">${esc(k)}=${esc(v.join("|"))}</span>`).join(" ") || "—"}</td><td class="num">${e.max_limit || 200}</td></tr>`).join("")}</table></div></div>`;
    } catch (_) { $("#info").innerHTML = '<div class="alert bad">Server bilan aloqa yo\'q</div>'; }
  });
})();
