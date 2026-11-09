# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Boshlang'ich sozlash: «Saqlash va sinxronlash» — bir bosishda token tekshiruvi, OTM profili va logotipi,
HEMIS API hujjatini (docs.json) yuklab olish va endpoint katalogini qurish.

Repoda hech qanday HEMIS hujjati yoki OTM ma'lumoti yo'q — hammasi shu yerda, admin kiritgan manzil/token orqali olinadi."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

from . import guard
from .admin_auth import audit, is_super
from .branding import clean_token, fetch_university_profile, logo_path, normalize_hemis_base
from .db import SessionLocal
from .models import Admin, Endpoint, Setting
from .security import client_ip, encrypt
from .state import bump_version, state

router = APIRouter(prefix="/api/admin/setup", tags=["Sozlash"])


async def _put(**values: tuple[str, bool]):
    async with SessionLocal() as db:
        for k, (v, secret) in values.items():
            row = await db.get(Setting, k) or Setting(key=k)
            row.value, row.is_secret = (encrypt(v) if secret and v else v), secret
            db.add(row)
        await db.commit()


async def full_sync(data: dict, by: str) -> dict:
    from .spec_update import _sha, apply_spec, compute_diff, discover_url, fetch_url, load_spec, new_filters_policy
    from .upstream import http
    steps: list[dict] = []

    def step(key, ok, msg, **extra):
        steps.append({"key": key, "ok": ok, "message": msg, **extra})
        return ok

    # 1) kiritilgan qiymatlarni saqlash
    upd = {}
    if data.get("hemis_base_url"):
        upd["hemis_base_url"] = (normalize_hemis_base(data["hemis_base_url"]), False)
    if data.get("hemis_admin_token"):
        upd["hemis_admin_token"] = (clean_token(data["hemis_admin_token"]), True)
    if data.get("docs_password"):
        upd["spec_password"] = (str(data["docs_password"]).strip(), True)
    if upd:
        await _put(**upd)
        await bump_version()
    await state.ensure_fresh()
    base, token = state.hemis_base, state.hemis_token
    if not base:
        step("save", False, "HEMIS manzili kiritilmagan")
        return {"ok": False, "steps": steps}
    step("save", True, f"Sozlamalar saqlandi · {base}")

    # 2) token
    if not token:
        step("token", False, "Token kiritilmagan — Backend API (statistika, ro'yxatlar) ishlamaydi")
    else:
        try:
            r = await http().get(base + "/v1/data/version-info",
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
            if r.status_code == 200:
                d = (r.json() or {}).get("data") or {}
                step("token", True, f"Token to'g'ri · HEMIS v{d.get('app_version', '?')}, API {d.get('api_version', '?')}")
            else:
                step("token", False, f"HEMIS tokenni qabul qilmadi ({r.status_code}). Token to'liq nusxalanganini va "
                                     "egasida «API User» roli borligini tekshiring")
        except Exception as ex:  # noqa: BLE001
            step("token", False, f"HEMIS ga ulanib bo'lmadi: {str(ex)[:120]}")

    # 3) OTM profili va logotip
    profile = await fetch_university_profile(save=True)
    if profile and profile.get("name"):
        vals = {"org_code": (profile.get("code", ""), False)}
        if not state.settings.get("org_name") or data.get("overwrite_org"):
            vals["org_name"] = (profile["name"], False)
        await _put(**vals)
        await bump_version()
        step("profile", True, f"OTM: {profile['name']} (kod {profile.get('code', '—')}"
                              + (f", {profile['region']}" if profile.get("region") else "") + ")"
                              + (" · logotip olindi" if logo_path() else ""))
    else:
        step("profile", False, "OTM profilini olib bo'lmadi (ochiq API javob bermadi) — nomini qo'lda kiriting")

    # 4) HEMIS API hujjati
    url = state.settings.get("spec_url", "")
    if not url:
        url, _tried = await discover_url(base)
        if url:
            await _put(spec_url=(url, False))
            await bump_version()
    if not url:
        step("docs", False, "HEMIS API hujjati (docs.json) manzili topilmadi — Endpointlar → Avto-sinxronlash da kiriting")
        return {"ok": False, "steps": steps}
    try:
        raw = await fetch_url(url, data.get("docs_password") or None)
        spec = load_spec(raw)
    except Exception as ex:  # noqa: BLE001
        msg = getattr(ex, "detail", str(ex))
        step("docs", False, f"Hujjatni yuklab bo'lmadi: {msg}", need_password="parol" in str(msg))
        return {"ok": False, "steps": steps}
    async with SessionLocal() as db:
        existing = (await db.execute(select(func.count(Endpoint.id)).where(Endpoint.in_spec.is_(True)))).scalar()
        diff = await compute_diff(db, spec)
        if diff["large_removal"] and existing:
            step("docs", False, f"Yangi hujjat {len(diff['removed'])} ta endpointni olib tashlaydi — ehtiyot uchun "
                                "qo'llanmadi. Endpointlar → HEMIS docs yangilash orqali ko'rib chiqing")
            return {"ok": False, "steps": steps}
        res = await apply_spec(db, spec, raw, new_filters_policy())
        await audit(db, by, "setup_sync", url[:256], {k: res[k] for k in ("added", "removed", "total")})
        await db.commit()
    await bump_version()
    step("docs", True, f"HEMIS API hujjati olindi (v{diff['info']['version'] or '?'}): {res['total']} ta endpoint · "
                       f"+{res['added']} yangi, {res['removed']} olib tashlangan")
    await guard.event("spec_applied", f"Sozlashda sinxronlandi: {res['total']} endpoint. Admin: {by}", alert=False)
    return {"ok": all(s["ok"] for s in steps), "steps": steps}


@router.post("/sync")
async def setup_sync(data: dict, request: Request, a: Admin = Depends(is_super)):
    res = await full_sync(data or {}, a.username)
    async with SessionLocal() as db:
        await audit(db, a.username, "setup_sync_run", "", {"ok": res["ok"]}, client_ip(request))
        await db.commit()
    return res
