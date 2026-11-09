/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Azimjon Makhkamov */
/* Kichik SVG grafik kutubxonasi (tashqi kutubxonasiz, CSP-mos). */
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const tip = () => document.getElementById("tip");
  const fmt = (n) => (n == null || n === "" ? "—" : Number(n).toLocaleString("en-US", { maximumFractionDigits: 1 }).replace(/,/g, " "));
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function showTip(html, ev) {
    const t = tip(); t.innerHTML = html; t.style.display = "block";
    const w = t.offsetWidth, h = t.offsetHeight;
    let x = ev.clientX + 14, y = ev.clientY + 14;
    if (x + w > innerWidth - 8) x = ev.clientX - w - 14;
    if (y + h > innerHeight - 8) y = ev.clientY - h - 14;
    t.style.left = x + "px"; t.style.top = y + "px";
  }
  function hideTip() { tip().style.display = "none"; }

  function el(tag, attrs, parent) {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  function niceMax(v) {
    if (v <= 0) return 4;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  /* Ustunli (stacked) vaqt qatori. series: [{key,label,color}], rows: [{label, tipLabel, <key>: n}] */
  function stackedColumns(container, rows, series, opts = {}) {
    container.innerHTML = "";
    container.classList.add("chart");
    const lg = document.createElement("div"); lg.className = "legend";
    lg.innerHTML = series.map((s) => `<span><i style="background:${s.color}"></i>${esc(s.label)}</span>`).join("");
    container.appendChild(lg);
    const W = Math.max(280, container.clientWidth), H = opts.height || 220;
    const m = { l: 44, r: 8, t: 8, b: 26 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const totals = rows.map((r) => series.reduce((a, s) => a + (r[s.key] || 0), 0));
    const max = niceMax(Math.max(...totals, 0));
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": opts.label || "grafik" }, container);
    for (let i = 0; i <= 4; i++) {
      const y = m.t + ih - (ih * i) / 4;
      el("line", { x1: m.l, x2: W - m.r, y1: y, y2: y, class: i ? "grid-line" : "axis" }, svg);
      const t = el("text", { x: m.l - 6, y: y + 4, "text-anchor": "end" }, svg); t.textContent = fmt((max * i) / 4);
    }
    const n = rows.length || 1, slot = iw / n, bw = Math.max(2, Math.min(28, slot - 2));
    const every = Math.ceil(n / Math.max(1, Math.floor(iw / 56)));
    rows.forEach((r, i) => {
      const x = m.l + i * slot + (slot - bw) / 2;
      let y = m.t + ih;
      const g = el("g", { class: "bar" }, svg);
      const visible = series.filter((s) => r[s.key] > 0);
      visible.forEach((s, j) => {
        const h = (r[s.key] / max) * ih;
        const top = j === visible.length - 1;
        const gap = j > 0 ? 2 : 0;
        const hh = Math.max(0, h - gap);
        if (top && hh > 4) {
          const rad = Math.min(4, bw / 2);
          el("path", { d: `M${x},${y - gap} v${-(hh - rad)} q0,${-rad} ${rad},${-rad} h${bw - 2 * rad} q${rad},0 ${rad},${rad} v${hh - rad} z`, fill: s.color }, g);
        } else el("rect", { x, y: y - gap - hh, width: bw, height: hh, fill: s.color }, g);
        y -= h;
      });
      if (i % every === 0) {
        const t = el("text", { x: x + bw / 2, y: H - 8, "text-anchor": "middle" }, svg); t.textContent = r.label;
      }
      const hit = el("rect", { x: m.l + i * slot, y: m.t, width: slot, height: ih, class: "hit" }, svg);
      hit.addEventListener("mousemove", (ev) => {
        container.classList.add("hovering"); g.classList.add("hl");
        showTip(`<b>${esc(r.tipLabel || r.label)}</b>` + series.map((s) => `<div class="r"><span><i style="background:${s.color}"></i>${esc(s.label)}</span><b>${fmt(r[s.key] || 0)}</b></div>`).join(""), ev);
      });
      hit.addEventListener("mouseleave", () => { container.classList.remove("hovering"); g.classList.remove("hl"); hideTip(); });
    });
  }

  /* Gorizontal bar: items [{name, value, sub}] */
  function hbars(container, items, opts = {}) {
    container.innerHTML = "";
    if (!items.length) { container.innerHTML = '<div class="empty">Ma\'lumot yo\'q</div>'; return; }
    const max = Math.max(...items.map((i) => +i.value || 0), 1);
    const total = items.reduce((a, i) => a + (+i.value || 0), 0);
    const list = opts.limit ? items.slice(0, opts.limit) : items;
    for (const it of list) {
      const row = document.createElement("div"); row.className = "hbar-row";
      const pct = total ? ((+it.value / total) * 100).toFixed(1) : 0;
      row.innerHTML = `<div class="n" title="${esc(it.name)}">${esc(it.name)}</div><div class="track"><div class="fill" style="width:${(+it.value / max) * 100}%;${opts.color ? "background:" + opts.color : ""}"></div></div><div class="v">${fmt(it.value)}${opts.suffix || ""}</div>`;
      row.addEventListener("mousemove", (ev) => showTip(`<b>${esc(it.name)}</b><div class="r"><span>${esc(opts.unit || "Soni")}</span><b>${fmt(it.value)}${opts.suffix || ""}</b></div>${opts.noPct ? "" : `<div class="r"><span>Ulushi</span><b>${pct}%</b></div>`}${it.sub ? `<div class="muted small">${esc(it.sub)}</div>` : ""}`, ev));
      row.addEventListener("mouseleave", hideTip);
      container.appendChild(row);
    }
    if (opts.limit && items.length > opts.limit) {
      const more = document.createElement("div"); more.className = "muted small"; more.textContent = `… yana ${items.length - opts.limit} ta`;
      container.appendChild(more);
    }
  }

  window.Charts = { stackedColumns, hbars, fmt, esc, hideTip };
})();
