/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Azimjon Makhkamov */
"use strict";
(async () => {
  const me = await fetch("/docs/me", { credentials: "same-origin" });
  if (me.status === 401) { location.reload(); return; }
  const m = await me.json();
  document.getElementById("who").textContent = m.name + " · " + m.docs_username;
  document.getElementById("kp").textContent = "kalit: hg_" + m.key_prefix + "_…";

  window.ui = SwaggerUIBundle({
    url: "/docs/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    docExpansion: "list",
    tryItOutEnabled: true,
    filter: true,
    displayRequestDuration: true,
    persistAuthorization: false,   // kalit brauzer xotirasida saqlanmaydi
    validatorUrl: null,
    defaultModelsExpandDepth: 0,
    syntaxHighlight: { activated: true, theme: "agate" },
    // docs sessiya cookie si faqat spec uchun; API so'rovlariga cookie yuborilmaydi
    requestInterceptor: (req) => { if (!new URL(req.url, location.href).pathname.startsWith("/docs/")) req.credentials = "omit"; return req; },
  });
})();

function connectKey() {
  const k = document.getElementById("hgkey").value.trim();
  const msg = document.getElementById("hgkeymsg");
  if (!/^hg_[0-9a-f]{10}_.+/.test(k)) { msg.textContent = "Kalit hg_ bilan boshlanishi kerak (administrator bergan kalit)"; msg.className = "hg-keymsg bad"; return; }
  if (window.ui) {
    window.ui.preauthorizeApiKey("gatewayKey", k);
    msg.textContent = "✓ Kalit ulandi. Endi endpointni oching → «Try it out» → «Execute». (Sahifa yangilansa qayta kiritasiz.)";
    msg.className = "hg-keymsg ok";
    document.getElementById("hgkey").value = "";
  }
}
document.getElementById("hgkeybtn").addEventListener("click", connectKey);
document.getElementById("hgkey").addEventListener("keydown", (e) => { if (e.key === "Enter") connectKey(); });

document.getElementById("logout").addEventListener("click", async () => {
  await fetch("/docs/logout", { method: "POST", credentials: "same-origin" });
  location.reload();
});
