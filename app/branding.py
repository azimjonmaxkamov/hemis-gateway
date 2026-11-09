# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""OTM (oliy ta'lim muassasasi) ma'lumotlari: nomi, logotipi; HEMIS manzilini normallashtirish; ochiq branding API."""
import re
from pathlib import Path

import httpx
from fastapi import APIRouter
from fastapi.responses import FileResponse, Response

from . import __author__, __copyright__, __license__, __title__, __url__, __version__
from .config import settings
from .state import state

router = APIRouter(tags=["Branding"])
LOGO_DIR = Path(settings.OPENAPI_PATH).parent


def normalize_hemis_base(url: str) -> str:
    """Har qanday HEMIS manzilini REST bazasiga keltiradi:
    https://student.otm.uz/rest/docs#/  -> https://student.otm.uz/rest
    https://student.otm.uz              -> https://student.otm.uz/rest"""
    u = (url or "").strip()
    if not u:
        return ""
    if not re.match(r"^https?://", u):
        u = "https://" + u
    u = re.split(r"[#?]", u, 1)[0].rstrip("/")
    m = re.match(r"^(https?://[^/]+)(/.*)?$", u)
    if not m:
        return u
    host, path = m.group(1), m.group(2) or ""
    i = path.find("/rest")
    return host + (path[:i + 5] if i >= 0 else "/rest")


def clean_token(t: str) -> str:
    """Nusxalashda qo'shilib qoladigan narsalarni olib tashlaydi: bo'shliqlar, qo'shtirnoq, 'Bearer ' prefiksi."""
    t = (t or "").strip().strip('"').strip("'").strip()
    if t.lower().startswith("bearer "):
        t = t[7:].strip()
    return re.sub(r"\s+", "", t)


def logo_path() -> Path | None:
    for ext in ("png", "jpg", "webp", "svg"):
        p = LOGO_DIR / f"branding-logo.{ext}"
        if p.exists():
            return p
    return None


async def fetch_university_profile(save: bool = True) -> dict | None:
    """HEMIS ochiq API sidan OTM nomi, kodi va logotipini oladi (token kerak emas)."""
    base = state.hemis_base
    if not base:
        return None
    try:
        async with httpx.AsyncClient(timeout=15, verify=settings.HEMIS_VERIFY_TLS, follow_redirects=True) as c:
            r = await c.get(base + "/v1/public/university-profile", headers={"Accept": "application/json"})
            d = (r.json() or {}).get("data") or {}
            out = {"name": d.get("name") or "", "code": str(d.get("code") or ""), "logo": d.get("logo") or "",
                   "type": (d.get("universityType") or {}).get("name", ""), "region": (d.get("soato") or {}).get("name", "")}
            if save and out["logo"].startswith(("http://", "https://")):
                lr = await c.get(out["logo"])
                ct = lr.headers.get("content-type", "")
                ext = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/svg+xml": "svg"}.get(ct.split(";")[0])
                if lr.status_code == 200 and ext and len(lr.content) < 512 * 1024:
                    for old in LOGO_DIR.glob("branding-logo.*"):
                        old.unlink(missing_ok=True)
                    (LOGO_DIR / f"branding-logo.{ext}").write_bytes(lr.content)
            return out
    except Exception:  # noqa: BLE001
        return None


def org_name() -> str:
    return state.settings.get("org_name", "")


def org_short() -> str:
    s = state.settings.get("org_short", "")
    if s:
        return s
    n = org_name()
    if not n:
        return ""
    words = [w for w in re.split(r"[\s\-]+", n) if w and w[0].isalpha()]
    return "".join(w[0].upper() for w in words)[:8] if len(words) > 2 else n


def public_base(request=None) -> str:
    v = state.settings.get("public_base_url", "") or settings.PUBLIC_BASE_URL
    if v and "example" not in v:
        return v.rstrip("/")
    if request is not None:
        return f"{request.url.scheme}://{request.url.netloc}"
    return v.rstrip("/")


def info() -> dict:
    return {"product": __title__, "version": __version__, "author": __author__, "license": __license__,
            "copyright": __copyright__, "url": __url__, "org_name": org_name(), "org_short": org_short(),
            "has_logo": logo_path() is not None, "configured": bool(state.hemis_base and state.hemis_token)}


@router.get("/api/public/branding", include_in_schema=False)
async def branding():
    await state.ensure_fresh()
    i = info()
    i.pop("configured")
    return i


@router.get("/branding/logo", include_in_schema=False)
async def logo():
    p = logo_path()
    if not p:
        return Response(status_code=404)
    return FileResponse(p, headers={"Cache-Control": "public, max-age=3600"})
