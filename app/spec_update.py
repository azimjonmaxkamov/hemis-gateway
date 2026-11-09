# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""HEMIS API hujjati (docs.json) yangilanishi: farqni oldindan ko'rish, qo'llash, versiyalar arxivi,
qaytarish (rollback), URL dan yuklash va kunlik avtomatik tekshiruv (faqat xabar beradi, o'zi qo'llamaydi)."""
import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from . import guard
from .admin_auth import audit, can_view, is_super
from .catalog import parse_openapi
from .config import settings
from .db import SessionLocal, get_db
from .kv import kv
from .models import Admin, Client, Endpoint, Permission, Setting
from .security import client_ip
from .state import bump_version, state

log = logging.getLogger("gateway.spec")
router = APIRouter(prefix="/api/admin/spec", tags=["HEMIS docs yangilash"])
MAX_SPEC = 20 * 1024 * 1024
_NAME_RE = re.compile(r"^\d{8}-\d{6}_[0-9a-f]{8}\.json$")
_transport = None   # testlar uchun (httpx transport almashtirish)


def specs_dir() -> Path:
    d = Path(settings.OPENAPI_PATH).parent / "specs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sha(raw: bytes) -> str:
    """Kanonik JSON bo'yicha xesh — bo'sh joylar/tartib farqi «o'zgarish» deb hisoblanmaydi."""
    try:
        raw = json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    except ValueError:
        pass
    return hashlib.sha256(raw).hexdigest()


def load_spec(raw: bytes) -> dict:
    try:
        spec = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Fayl JSON formatida emas")
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict) or not spec["paths"]:
        raise HTTPException(400, "Bu OpenAPI (swagger) hujjati emas: 'paths' bo'limi topilmadi")
    if not (spec.get("openapi") or spec.get("swagger")):
        raise HTTPException(400, "Bu OpenAPI (swagger) hujjati emas: 'openapi' versiyasi ko'rsatilmagan")
    return spec


PW_FORM = re.compile(r'name=["\']swagger_password["\']', re.I)


def docs_password() -> str:
    return state.settings.get("spec_password", "")


async def _read_limited(r: httpx.Response) -> bytes:
    buf = bytearray()
    async for chunk in r.aiter_bytes():
        buf += chunk
        if len(buf) > MAX_SPEC:
            raise HTTPException(400, "Hujjat 20 MB dan katta")
    return bytes(buf)


async def _swagger_login(c: httpx.AsyncClient, url: str, html: str, password: str):
    """HEMIS docs sahifasi parol bilan himoyalangan: forma (_csrf + swagger_password) orqali kirish."""
    m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
    # Forma action'siz bo'lsa parol aynan shu sahifaga yuboriladi (brauzer kabi), url o'zgartirilmaydi.
    action = str(httpx.URL(url).join(m.group(1))) if m else url
    csrf = re.search(r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']', html, re.I) or \
        re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']_csrf["\']', html, re.I)
    data = {"swagger_password": password}
    if csrf:
        data["_csrf"] = csrf.group(1)
    # Ba'zi HEMIS docs gate'lari "Accept: text/html" POST'ga 406 qaytaradi — brauzer kabi */* yuboramiz.
    r = await c.post(action, data=data, headers={"Accept": "*/*"})
    if r.status_code >= 400 and PW_FORM.search(r.text or ""):
        raise HTTPException(400, "HEMIS docs paroli noto'g'ri")


async def fetch_url(url: str, password: str | None = None) -> bytes:
    """docs.json ni yuklaydi. HEMIS docs parol bilan himoyalangan bo'lsa (swagger_password), avval kiradi."""
    if not re.match(r"^https?://", url or ""):
        raise HTTPException(400, "URL http(s):// bilan boshlanishi kerak")
    password = password if password is not None else docs_password()
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=settings.HEMIS_VERIFY_TLS,
                                     transport=_transport) as c:
            for attempt in (1, 2):
                async with c.stream("GET", url, headers={"Accept": "application/json"}) as r:
                    body = await _read_limited(r)
                    ctype = r.headers.get("content-type", "")
                    status = r.status_code
                if status == 200 and "html" not in ctype:
                    return body
                text = body[:20000].decode("utf-8", "ignore")
                if PW_FORM.search(text) and attempt == 1:
                    if not password:
                        raise HTTPException(400, "HEMIS docs parol bilan himoyalangan — sinxronlash sozlamalarida "
                                                 "«HEMIS docs paroli»ni kiriting")
                    await _swagger_login(c, url, text, password)
                    continue
                if PW_FORM.search(text):
                    raise HTTPException(400, "HEMIS docs paroli noto'g'ri")
                raise HTTPException(400, f"URL {status} javob qaytardi")
    except httpx.HTTPError as ex:
        raise HTTPException(400, f"URL dan yuklab bo'lmadi: {str(ex)[:150]}")
    raise HTTPException(400, "Hujjatni yuklab bo'lmadi")


DISCOVER_SUFFIXES = ["/docs.json", "/docs/json", "/swagger.json", "/openapi.json", "/docs/swagger.json",
                     "/v1/docs.json", "/docs?format=json", "/api-docs.json", "/docs"]


async def discover_url(base: str | None = None) -> tuple[str | None, list]:
    """HEMIS REST manzilidan docs.json qayerda berilishini o'zi topadi."""
    base = (base or state.hemis_base).rstrip("/")
    root = re.sub(r"(https?://[^/]+).*", r"\1", base)
    cands = [base + s for s in DISCOVER_SUFFIXES] + [root + s for s in ("/docs.json", "/swagger.json", "/openapi.json")]
    tried = []
    async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=settings.HEMIS_VERIFY_TLS, transport=_transport) as c:
        i = 0
        while i < len(cands) and i < 25:
            u = cands[i]
            i += 1
            try:
                r = await c.get(u, headers={"Accept": "application/json, text/html"})
            except httpx.HTTPError as ex:
                tried.append({"url": u, "result": str(ex)[:60]})
                continue
            ct = r.headers.get("content-type", "")
            if PW_FORM.search(r.text[:20000] if "html" in ct else "") and u.endswith(".json"):
                tried.append({"url": u, "result": "topildi (parol bilan himoyalangan)"})
                return u, tried
            if r.status_code == 200 and len(r.content) < MAX_SPEC:
                try:
                    load_spec(r.content)
                    tried.append({"url": u, "result": "topildi"})
                    return u, tried
                except HTTPException:
                    pass
                if "html" in ct:   # swagger UI sahifasi bo'lsa — ichidan json manzilini qidiramiz
                    for m in re.findall(r"""(?:url|spec-url|href)\s*[:=]\s*["']([^"']+\.json[^"']*)["']""", r.text)[:5]:
                        nu = str(httpx.URL(u).join(m))
                        if nu not in cands:
                            cands.append(nu)
            tried.append({"url": u, "result": f"{r.status_code} {ct[:30]}"})
    return None, tried


# ---------------- farq (diff) ----------------

async def compute_diff(db: AsyncSession, spec: dict) -> dict:
    items = {(i["method"], i["path"]): i for i in parse_openapi(spec)}
    eps = (await db.execute(select(Endpoint))).scalars().all()
    old = {(e.method, e.path): e for e in eps if e.in_spec}
    removed_before = {(e.method, e.path) for e in eps if not e.in_spec}
    clients = (await db.execute(select(Client).options(selectinload(Client.permissions)))).scalars().all()
    by_ep: dict[int, list] = {}
    for c in clients:
        for p in c.permissions:
            by_ep.setdefault(p.endpoint_id, []).append((c, p))

    added, removed, changed, impacts = [], [], [], []
    for k, it in items.items():
        if k not in old:
            added.append({"method": k[0], "path": k[1], "summary": it["summary"], "group": it["group"],
                          "restored": k in removed_before})
    for k, e in old.items():
        if k not in items:
            users = [c.name for c, _ in by_ep.get(e.id, [])]
            removed.append({"method": k[0], "path": k[1], "summary": e.summary, "clients": users})
            for c, _ in by_ep.get(e.id, []):
                impacts.append({"level": "high", "client": c.name, "client_id": c.id, "endpoint": f"{k[0]} {k[1]}",
                                "message": "endpoint hujjatdan olib tashlanadi — mijoz so'rovlari 410 qaytaradi"})
            continue
        new_q = {p["name"] for p in items[k]["params"] if p["in"] == "query"}
        old_q = {p["name"] for p in (e.params or []) if p.get("in") == "query"}
        pa, pr = sorted(new_q - old_q), sorted(old_q - new_q)
        sum_changed = (items[k]["summary"] or "") != (e.summary or "")
        if pa or pr or sum_changed or items[k]["has_body"] != e.has_body:
            changed.append({"method": k[0], "path": k[1], "params_added": pa, "params_removed": pr,
                            "summary_changed": sum_changed, "body_changed": items[k]["has_body"] != e.has_body})
        for c, p in by_ep.get(e.id, []):
            lost_locks = [n for n in (p.locked_params or {}) if n in pr]
            if lost_locks:
                impacts.append({"level": "high", "client": c.name, "client_id": c.id, "endpoint": f"{k[0]} {k[1]}",
                                "message": f"qulflangan filtr(lar) yo'qoladi: {', '.join(lost_locks)} — bu endpoint mijoz "
                                           f"uchun rad etiladi (xavfsizlik uchun), ruxsatni qayta sozlang"})
            lost_allowed = [n for n in (p.allowed_params or []) if n in pr]
            if lost_allowed:
                impacts.append({"level": "info", "client": c.name, "client_id": c.id, "endpoint": f"{k[0]} {k[1]}",
                                "message": f"ruxsat berilgan filtr(lar) yo'qoladi: {', '.join(lost_allowed)}"})
            if pa and p.allowed_params is None:
                impacts.append({"level": "warn", "client": c.name, "client_id": c.id, "endpoint": f"{k[0]} {k[1]}",
                                "message": f"«barcha filtrlar» yoqilgan — yangi filtr(lar) avtomatik ruxsat oladi: "
                                           f"{', '.join(pa)}"})
            sk_lost = [pp["name"] for pp in (e.params or []) if pp.get("scope_key") and pp["name"] in pr]
            if sk_lost and c.scope:
                impacts.append({"level": "warn", "client": c.name, "client_id": c.id, "endpoint": f"{k[0]} {k[1]}",
                                "message": f"doira filtri yo'qoladi: {', '.join(sk_lost)} — qat'iy rejimda endpoint bloklanadi"})
    total_old = len(old) or 1
    return {
        "info": {"title": (spec.get("info") or {}).get("title", ""), "version": (spec.get("info") or {}).get("version", ""),
                 "paths": len(spec.get("paths", {})), "operations": len(items)},
        "current": {"operations": len(old)},
        "added": sorted(added, key=lambda x: x["path"]), "removed": sorted(removed, key=lambda x: x["path"]),
        "changed": sorted(changed, key=lambda x: x["path"]),
        "impacts": sorted(impacts, key=lambda x: {"high": 0, "warn": 1, "info": 2}[x["level"]]),
        "large_removal": len(removed) / total_old > 0.3 and len(removed) > 5,
        "no_changes": not (added or removed or changed),
    }


def new_filters_policy() -> str:
    return state.settings.get("spec_new_filters") or "freeze"


def is_risky(diff: dict) -> tuple[bool, list[str]]:
    reasons = []
    if diff["large_removal"]:
        reasons.append(f"{len(diff['removed'])} ta endpoint olib tashlanadi (30% dan ko'p)")
    high = [i for i in diff["impacts"] if i["level"] == "high"]
    if high:
        reasons.append(f"{len(high)} ta jiddiy ta'sir: " + "; ".join(f"{i['client']} — {i['endpoint']}" for i in high[:5]))
    return bool(reasons), reasons


async def apply_spec(db: AsyncSession, spec: dict, raw: bytes, new_filters: str | None = None) -> dict:
    """Hujjatni qo'llaydi va ruxsat qoidalarini yangi tuzilmaga moslaydi:
    - olib tashlangan filtrlar mijozlarning «ruxsat etilgan filtrlar» ro'yxatidan tozalanadi;
    - new_filters="freeze": «barcha filtrlar» yoqilgan mijozlarga yangi filtrlar avtomatik berilmaydi
      (ularning ro'yxati eski filtrlar bilan qotiriladi); "allow": yangi filtrlar ham ruxsat oladi;
    - qulflangan filtr yo'qolsa qulf saqlanadi (endpoint rad etiladi — xavfsiz tomonga)."""
    new_filters = new_filters or new_filters_policy()
    items = parse_openapi(spec)
    keys = {(i["method"], i["path"]) for i in items}
    existing = {(e.method, e.path): e for e in (await db.execute(select(Endpoint))).scalars()}
    perms_by_ep: dict[int, list] = {}
    for pm in (await db.execute(select(Permission))).scalars():
        perms_by_ep.setdefault(pm.endpoint_id, []).append(pm)
    now = datetime.now(timezone.utc)
    added = updated = removed = restored = frozen = cleaned = 0
    for it in items:
        e = existing.get((it["method"], it["path"]))
        if e is None:
            db.add(Endpoint(**it))   # yangi endpoint hech bir mijozga yoqilmagan holda qo'shiladi
            added += 1
            continue
        old_sk = {p["name"]: p.get("scope_key") for p in (e.params or [])}
        for p in it["params"]:
            if p["name"] in old_sk:
                p["scope_key"] = old_sk[p["name"]]   # admin sozlagan doira bog'lanishi saqlanadi
        old_q = {p["name"] for p in (e.params or []) if p.get("in") == "query"}
        new_q = {p["name"] for p in it["params"] if p["in"] == "query"}
        p_added, p_removed = new_q - old_q, old_q - new_q
        for pm in perms_by_ep.get(e.id, []):
            if pm.allowed_params is None:
                if p_added and new_filters == "freeze":
                    pm.allowed_params = sorted(old_q)
                    frozen += 1
            elif p_removed & set(pm.allowed_params):
                pm.allowed_params = [x for x in pm.allowed_params if x not in p_removed]
                cleaned += 1
        e.group, e.summary, e.description = it["group"], it["summary"], it["description"]
        e.params, e.has_body = it["params"], it["has_body"]
        if not e.in_spec:
            e.in_spec, e.removed_at = True, None
            restored += 1
        updated += 1
    for k, e in existing.items():
        if k not in keys and e.in_spec:
            e.in_spec, e.removed_at = False, now   # o'chirilmaydi: ruxsatlar va loglar saqlanadi
            removed += 1
    sha = _sha(raw)
    name = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}_{sha[:8]}.json"
    d = specs_dir()
    if not any(p.name.endswith(f"_{sha[:8]}.json") for p in d.glob("*.json")):
        (d / name).write_bytes(raw)
    else:
        name = next(p.name for p in d.glob(f"*_{sha[:8]}.json"))
    Path(settings.OPENAPI_PATH).write_bytes(raw)
    for k, v in (("spec_current", name), ("spec_applied_at", now.isoformat())):
        row = await db.get(Setting, k) or Setting(key=k)
        row.value = v
        db.add(row)
    await db.commit()
    return {"added": added, "updated": updated, "removed": removed, "restored": restored, "total": len(items),
            "version_file": name, "perms_frozen": frozen, "perms_cleaned": cleaned}


async def ensure_baseline():
    """Birinchi ishga tushishda joriy docs.json ni arxivga 'boshlang'ich versiya' sifatida qo'yadi."""
    p = Path(settings.OPENAPI_PATH)
    d = specs_dir()
    if p.exists() and not any(d.glob("*.json")):
        raw = p.read_bytes()
        (d / f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}_{_sha(raw)[:8]}.json").write_bytes(raw)


# ---------------- API ----------------

async def _read_source(file: UploadFile | None, url: str | None, version: str | None) -> tuple[bytes, str]:
    if file is not None and file.filename:
        raw = await file.read()
        if len(raw) > MAX_SPEC:
            raise HTTPException(400, "Fayl 20 MB dan katta")
        return raw, f"fayl: {file.filename}"
    if url:
        return await fetch_url(url.strip()), f"URL: {url.strip()}"
    if version:
        if not _NAME_RE.match(version) or not (specs_dir() / version).exists():
            raise HTTPException(404, "Bunday versiya topilmadi")
        return (specs_dir() / version).read_bytes(), f"arxiv: {version}"
    raise HTTPException(400, "Fayl, URL yoki arxiv versiyasini tanlang")


@router.post("/preview")
async def preview(file: UploadFile | None = File(None), url: str | None = Form(None), version: str | None = Form(None),
                  a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    raw, src = await _read_source(file, url, version)
    spec = load_spec(raw)
    diff = await compute_diff(db, spec)
    diff["source"] = src
    diff["sha"] = _sha(raw)[:12]
    diff["same_as_current"] = Path(settings.OPENAPI_PATH).exists() and _sha(Path(settings.OPENAPI_PATH).read_bytes()) == _sha(raw)
    return diff


@router.post("/apply")
async def apply(request: Request, file: UploadFile | None = File(None), url: str | None = Form(None),
                version: str | None = Form(None), confirm_large: bool = Form(False),
                a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    raw, src = await _read_source(file, url, version)
    spec = load_spec(raw)
    diff = await compute_diff(db, spec)
    if diff["large_removal"] and not confirm_large:
        raise HTTPException(409, f"{len(diff['removed'])} ta endpoint olib tashlanadi — bu noto'g'ri fayl bo'lishi mumkin. "
                                 "Ishonchingiz komil bo'lsa, tasdiqlab qayta yuboring")
    res = await apply_spec(db, spec, raw)
    res["source"] = src
    await audit(db, a.username, "spec_apply", src[:256], {k: res[k] for k in ("added", "updated", "removed", "restored",
                                                                                "version_file")}, client_ip(request))
    await db.commit()
    await bump_version()
    await guard.event("spec_applied", f"HEMIS API hujjati yangilandi ({src}): +{res['added']} yangi, {res['removed']} olib "
                      f"tashlandi, {len(diff['changed'])} o'zgargan. Admin: {a.username}", "info", alert=False)
    return res


@router.get("/versions")
async def versions(a: Admin = Depends(can_view)):
    await state.ensure_fresh()
    cur = state.settings.get("spec_current", "")
    out = []
    for p in sorted(specs_dir().glob("*.json"), reverse=True):
        if not _NAME_RE.match(p.name):
            continue
        try:
            info = json.loads(p.read_bytes()).get("info", {})
            ops = sum(1 for v in json.loads(p.read_bytes()).get("paths", {}).values() for m in v
                      if m in ("get", "post", "put", "patch", "delete"))
        except ValueError:
            info, ops = {}, 0
        ts = datetime.strptime(p.name[:15], "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
        out.append({"name": p.name, "saved_at": ts.isoformat(), "size": p.stat().st_size, "version": info.get("version", ""),
                    "operations": ops, "current": p.name == cur})
    if out and not any(v["current"] for v in out):
        try:
            cur_sha = _sha(Path(settings.OPENAPI_PATH).read_bytes())[:8]
            for v in out:
                v["current"] = v["name"].endswith(f"_{cur_sha}.json")
        except OSError:
            pass
    return {"versions": out, "spec_url": state.settings.get("spec_url", "")}


@router.get("/versions/{name}/download")
async def download(name: str, a: Admin = Depends(can_view)):
    from fastapi.responses import FileResponse
    if not _NAME_RE.match(name) or not (specs_dir() / name).exists():
        raise HTTPException(404, "Topilmadi")
    return FileResponse(specs_dir() / name, media_type="application/json", filename=f"hemis-docs-{name}")


SYNC_MODES = {
    "off": "O'chirilgan",
    "notify": "Faqat xabar berish",
    "safe": "Xavfsiz o'zgarishlarni avtomatik qo'llash",
    "full": "Hammasini avtomatik qo'llash",
}


def sync_cfg() -> dict:
    st = state.settings
    mode = st.get("spec_sync_mode")
    if not mode:  # eski versiyadagi sozlama bilan moslik
        mode = "notify" if st.get("spec_autocheck") == "1" else "safe"
    try:
        hours = int(st.get("spec_sync_hours") or 6)
    except ValueError:
        hours = 6
    return {"mode": mode if mode in SYNC_MODES else "safe", "hours": hours if hours in (1, 3, 6, 12, 24) else 6,
            "url": st.get("spec_url", ""), "new_filters": new_filters_policy()}


def _cfg_out(cfg: dict) -> dict:
    return {**cfg, "password_set": bool(docs_password())}


@router.get("/sync")
async def get_sync(a: Admin = Depends(can_view)):
    await state.ensure_fresh()
    cfg = _cfg_out(sync_cfg())
    st = state.settings
    return {**cfg, "modes": SYNC_MODES, "last_check": st.get("spec_last_check", ""),
            "last_result": st.get("spec_last_result", ""), "last_status": st.get("spec_last_status", ""),
            "pending": st.get("spec_pending", "")}


@router.put("/sync")
async def put_sync(data: dict, request: Request, a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    url = str(data.get("url") or "").strip()
    if url and not re.match(r"^https?://", url):
        raise HTTPException(400, "URL http(s):// bilan boshlanishi kerak")
    mode = data.get("mode", "safe")
    hours = str(data.get("hours", 6))
    nf = data.get("new_filters", "freeze")
    if mode not in SYNC_MODES or hours not in ("1", "3", "6", "12", "24") or nf not in ("freeze", "allow"):
        raise HTTPException(400, "Noto'g'ri qiymat")
    for k, v in (("spec_url", url), ("spec_sync_mode", mode), ("spec_sync_hours", hours), ("spec_new_filters", nf)):
        row = await db.get(Setting, k) or Setting(key=k)
        row.value = v
        db.add(row)
    pw = data.get("password")
    if pw is not None and str(pw) != "":
        from .security import encrypt
        row = await db.get(Setting, "spec_password") or Setting(key="spec_password")
        row.value, row.is_secret = encrypt(str(pw)) if str(pw) != "-" else "", True   # "-" = parolni o'chirish
        db.add(row)
    await audit(db, a.username, "spec_sync_settings", url[:256], {"mode": mode, "hours": hours, "new_filters": nf},
                client_ip(request))
    await db.commit()
    await bump_version()
    await kv.delete("spec:autocheck")   # yangi sozlama bilan keyingi tekshiruv tezroq bo'lsin
    return {"ok": True}


@router.post("/discover")
async def discover(a: Admin = Depends(is_super)):
    await state.ensure_fresh()
    url, tried = await discover_url()
    return {"found": url, "tried": tried}


@router.post("/check-now")
async def check_now(a: Admin = Depends(is_super)):
    return await run_check(force=True, by=a.username)


# ---------------- avtomatik sinxronlash ----------------

async def _save_settings(**kv_: str):
    async with SessionLocal() as db:
        for k, v in kv_.items():
            row = await db.get(Setting, k) or Setting(key=k)
            row.value = v
            db.add(row)
        await db.commit()


async def run_check(force: bool = False, by: str = "system") -> dict:
    """HEMIS dan docs.json ni oladi, farqni hisoblaydi va rejimga qarab qo'llaydi yoki xabar beradi."""
    await state.ensure_fresh()
    cfg = sync_cfg()
    now = datetime.now(timezone.utc)
    url = cfg["url"]

    async def done(status: str, msg: str, **extra):
        await _save_settings(spec_last_check=now.isoformat(), spec_last_result=msg, spec_last_status=status,
                             **{k: v for k, v in extra.items()})
        await bump_version()
        return {"ok": status not in ("error",), "status": status, "message": msg,
                "changed": status in ("applied", "pending", "notified")}

    if not url:
        found, _ = await discover_url()
        if not found:
            return await done("error", "HEMIS docs manzili topilmadi — Sinxronlash sozlamalarida URL ni kiriting")
        url = found
        await _save_settings(spec_url=url)
    try:
        raw = await fetch_url(url)
        spec = load_spec(raw)
    except HTTPException as ex:
        if cfg["mode"] != "off":
            await guard.event("spec_sync_error", f"HEMIS docs ni olib bo'lmadi: {ex.detail}", "warn", dedupe="specerr")
        return await done("error", f"Xato: {ex.detail}")
    cur = Path(settings.OPENAPI_PATH)
    if cur.exists() and _sha(cur.read_bytes()) == _sha(raw):
        return await done("same", "O'zgarish yo'q — tizim HEMIS bilan bir xil", spec_pending="")
    async with SessionLocal() as db:
        diff = await compute_diff(db, spec)
    summary = (f"+{len(diff['added'])} yangi, {len(diff['removed'])} olib tashlangan, {len(diff['changed'])} o'zgargan "
               f"endpoint (v{diff['info']['version'] or '?'})")
    risky, reasons = is_risky(diff)
    sha = _sha(raw)[:16]
    mode = cfg["mode"]
    fresh = await kv.setnx(f"specalert:{sha}", "1", 30 * 86400) or force

    if mode in ("safe", "full") and not diff["large_removal"] and (mode == "full" or not risky):
        async with SessionLocal() as db:
            res = await apply_spec(db, spec, raw, cfg["new_filters"])
            await audit(db, by, "spec_auto_apply", url[:256], {k: res[k] for k in (
                "added", "removed", "restored", "perms_frozen", "perms_cleaned")})
            await db.commit()
        await bump_version()
        extra = f" Ruxsatlar moslandi: {res['perms_cleaned']} ta tozalandi, {res['perms_frozen']} ta qotirildi." \
            if res["perms_cleaned"] or res["perms_frozen"] else ""
        warn = (" Diqqat: " + " ".join(reasons)) if reasons else ""
        msg = f"Avtomatik qo'llandi: {summary}.{extra}{warn}"
        await guard.event("spec_auto_applied", msg, "warn" if reasons else "info",
                          details={"url": url, "sha": sha}, dedupe=None if force else sha)
        return await done("applied", msg, spec_pending="")

    if diff["no_changes"] and mode in ("safe", "full"):
        async with SessionLocal() as db:
            await apply_spec(db, spec, raw, cfg["new_filters"])   # faqat tavsiflar — xavfsiz
        await bump_version()
        return await done("applied", "Faqat tavsiflar yangilandi (tuzilma o'zgarmagan)", spec_pending="")

    why = ("; ".join(reasons)) if reasons else "faqat xabar berish rejimi"
    msg = (f"Yangi versiya: {summary}. Tasdiq kerak — {why}. Panel: Endpointlar → HEMIS docs yangilash → URL.")
    if fresh:
        await guard.event("spec_changed", msg, "high" if risky else "warn", details={"url": url, "sha": sha},
                          dedupe=None if force else sha)
    return await done("pending" if mode in ("safe", "full") else "notified", msg, spec_pending=sha)


async def autocheck_loop():
    await asyncio.sleep(60)
    while True:
        try:
            await state.ensure_fresh()
            cfg = sync_cfg()
            if cfg["mode"] != "off" and await kv.setnx("spec:autocheck", "1", cfg["hours"] * 3600):
                res = await run_check()
                log.info("HEMIS docs sinxronlash: %s", res.get("message"))
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("docs avtomatik sinxronlashda xato")
        await asyncio.sleep(300)
