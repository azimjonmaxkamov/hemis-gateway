/* SPDX-License-Identifier: Apache-2.0 — Copyright (c) 2026 Azimjon Makhkamov */
"use strict";
(async () => {
  let b;
  try { b = await fetch("/api/public/branding").then((r) => r.json()); } catch (_) { return; }
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
  if (b.org_name) { set("bname", esc(b.org_name)); document.title = document.title.replace("HEMIS", (b.org_short || "HEMIS")); }
  if (b.org_short) set("bshort", esc(b.org_short));
  if (b.has_logo) set("blogo", '<img class="logo" src="/branding/logo" alt="" style="object-fit:contain;background:#fff">');
  set("pfoot", `${esc(b.product)} v${esc(b.version)} · © 2026 ${b.url ? `<a href="${esc(b.url)}" target="_blank" rel="noopener">${esc(b.author)}</a>` : esc(b.author)} · ${esc(b.license)}`);
})();
