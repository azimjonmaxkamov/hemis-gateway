/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Azimjon Makhkamov */
"use strict";
const $ = (s) => document.querySelector(s);
async function loadCaptcha() {
  const r = await fetch("/api/captcha").then((x) => x.json());
  $("#capf").style.display = "block"; $("#capimg").src = r.image; $("[name=captcha_id]").value = r.captcha_id;
  $("[name=captcha]").value = ""; $("[name=captcha]").focus();
}
$("#capnew").addEventListener("click", loadCaptcha);
$("#f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = Object.fromEntries(new FormData(e.target));
  const err = $("#err");
  err.style.display = "none";
  try {
    const r = await fetch("/docs/login", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "hg-docs" },
      body: JSON.stringify(fd),
    });
    if (r.ok) { location.reload(); return; }
    const d = await r.json().catch(() => ({}));
    if (r.status === 428 || $("#capf").style.display === "block") await loadCaptcha();
    err.textContent = d.detail || d.error || "Kirib bo'lmadi";
  } catch (_) { err.textContent = "Server bilan aloqa yo'q"; }
  err.style.display = "block";
});
