# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Mijozlar uchun Swagger hujjatlari (/docs).

Har bir mijoz admin bergan login/parol bilan kiradi va faqat O'ZIGA ruxsat berilgan endpointlar,
filtrlar va qiymatlarni ko'radi (HEMIS ning o'z swagger sahifasiga o'xshash, lekin filtrlangan).
"""
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import __copyright__, __license__, __title__, __version__
from .branding import org_name, org_short, public_base
from .catalog import ALWAYS_ALLOWED_PARAMS, PERSONAL_FIELDS, SCOPE_KEYS, _resolve
from .config import settings
from .db import get_db
from . import guard
from .captcha import verify_captcha
from .kv import kv
from .models import Client
from .security import client_ip, verify_password
from .state import state

router = APIRouter(tags=["Docs"])
COOKIE = "hg_docs"
STATIC = Path(__file__).parent / "static"
SESSION_HOURS = 12

_spec_cache: dict = {"mtime": None, "spec": None}


_dummy: list[str] = []


def _dummy_hash() -> str:
    if not _dummy:
        from .security import hash_password
        _dummy.append(hash_password("timing-equalizer"))
    return _dummy[0]


def _raw_spec() -> dict:
    p = Path(settings.OPENAPI_PATH)
    if not p.exists():
        return {"paths": {}, "components": {}, "info": {}}
    m = p.stat().st_mtime
    if _spec_cache["mtime"] != m:
        _spec_cache["spec"] = json.loads(p.read_text(encoding="utf-8"))
        _spec_cache["mtime"] = m
    return _spec_cache["spec"]


# ---------------- sessiya ----------------

def _token(c: Client) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(c.id), "dv": c.docs_token_version, "typ": "docs", "iat": now,
                       "exp": now + timedelta(hours=SESSION_HOURS)}, settings.SECRET_KEY, algorithm="HS256")


async def _session_client(request: Request, db: AsyncSession) -> Client | None:
    tok = request.cookies.get(COOKIE)
    if not tok:
        return None
    try:
        p = jwt.decode(tok, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if p.get("typ") != "docs":
        return None
    c = await db.get(Client, int(p["sub"]))
    if not c or not c.is_active or not c.docs_enabled or c.docs_token_version != p.get("dv"):
        return None
    return c


async def docs_client(request: Request, db: AsyncSession = Depends(get_db)) -> Client:
    c = await _session_client(request, db)
    if not c:
        raise HTTPException(401, "Hujjatlarga kirish uchun login qiling")
    return c


# ---------------- sahifalar ----------------

@router.get("/docs", include_in_schema=False)
async def docs_page(request: Request, db: AsyncSession = Depends(get_db)):
    c = await _session_client(request, db)
    return FileResponse(STATIC / ("docs.html" if c else "docs-login.html"), headers={"Cache-Control": "no-store"})


class LoginIn(BaseModel):
    username: str
    password: str
    captcha_id: str | None = None
    captcha: str | None = None


@router.post("/docs/login", include_in_schema=False)
async def docs_login(data: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    if request.headers.get("x-requested-with") != "hg-docs":
        raise HTTPException(403, "CSRF")
    ip = client_ip(request)
    user = data.username.strip().lower()[:64]
    if await kv.incr(f"docslogin:ip:{ip}", 600) > 30 or await kv.incr(f"docslogin:u:{user}", 900) > 10:
        raise HTTPException(429, "Juda ko'p urinish. Birozdan so'ng qayta urining")
    if await guard.captcha_needed("docs", ip) and not await verify_captcha(data.captcha_id, data.captcha):
        raise HTTPException(428, "Captcha noto'g'ri yoki kiritilmagan" if data.captcha else "Captcha kiriting")
    c = (await db.execute(select(Client).where(Client.docs_username == user))).scalar_one_or_none()
    if c and c.docs_password_hash:
        ok = verify_password(data.password, c.docs_password_hash)
    else:
        verify_password(data.password, _dummy_hash())  # login mavjudligini vaqt bo'yicha bilib bo'lmasligi uchun
        ok = False
    if not ok:
        await guard.login_failed("docs", ip, user)
        raise HTTPException(401, "Login yoki parol noto'g'ri")
    await guard.login_ok("docs", ip)
    if not c.is_active or not c.docs_enabled:
        raise HTTPException(403, "Hujjatlarga kirish o'chirilgan. Administratorga murojaat qiling")
    c.docs_last_login_at = datetime.now(timezone.utc)
    await db.commit()
    response.set_cookie(COOKIE, _token(c), httponly=True, secure=settings.ENV == "production",
                        samesite="strict", max_age=SESSION_HOURS * 3600, path="/docs")
    return {"ok": True}


@router.post("/docs/logout", include_in_schema=False)
async def docs_logout(response: Response):
    response.delete_cookie(COOKIE, path="/docs")
    return {"ok": True}


@router.get("/docs/me", include_in_schema=False)
async def docs_me(c: Client = Depends(docs_client)):
    return {"name": c.name, "docs_username": c.docs_username, "key_prefix": c.key_prefix}


# ---------------- filtrlangan OpenAPI ----------------

@router.get("/docs/openapi.json", include_in_schema=False)
async def docs_openapi(request: Request, c: Client = Depends(docs_client)):
    await state.ensure_fresh()
    sc = next((x for x in state.clients.values() if x.id == c.id), None)
    if sc is None:
        raise HTTPException(401, "Sessiya yaroqsiz")
    base = public_base(request)
    spec = build_client_spec(_raw_spec(), sc, state.endpoints, base)
    return JSONResponse(spec, headers={"Cache-Control": "no-store"})


def _param_note(p: dict, text: str):
    p["description"] = ((p.get("description") or "") + f"\n\n**Gateway:** {text}").strip()


def build_client_spec(raw: dict, client, endpoints: dict, base_url: str) -> dict:
    scope = {k: [str(x) for x in v] for k, v in (client.scope or {}).items() if v}
    paths: dict = {}
    used_tags: set = set()
    for eid, perm in client.perms.items():
        ep = endpoints.get(eid)
        if not ep or not ep.is_enabled or not ep.in_spec:
            continue
        src = raw.get("paths", {}).get(ep.path, {})
        op = copy.deepcopy(src.get(ep.method.lower(), {"summary": ep.summary, "responses": {"200": {"description": "OK"}}}))
        common = [_resolve(raw, x) for x in src.get("parameters", [])]
        params = [copy.deepcopy(_resolve(raw, x)) for x in common + op.get("parameters", [])]

        documented = {p["name"] for p in ep.params if p.get("in") == "query"}
        locked = {k: [str(x) for x in v] for k, v in (perm.locked_params or {}).items() if v}
        scope_map: dict[str, list[str]] = {}
        if scope and ep.auth_mode in ("admin", "fast"):
            for p in ep.params:
                if p.get("scope_key") in scope:
                    scope_map.setdefault(p["scope_key"], []).append(p["name"])
        scope_params = {n: scope[k] for k, names in scope_map.items() for n in names}
        allowed = documented if perm.allowed_params is None else (set(perm.allowed_params) & documented)
        allowed = allowed | set(locked) | set(scope_params) | ALWAYS_ALLOWED_PARAMS

        out = []
        for p in params:
            loc, name = p.get("in"), p.get("name")
            if loc == "header" or (loc == "query" and name == "token" and ep.auth_mode == "fast"):
                continue
            if loc == "query" and name not in allowed:
                continue
            schema = p.setdefault("schema", {"type": "string"})
            vals = locked.get(name) or scope_params.get(name)
            if vals:
                schema.pop("example", None)
                schema["enum"] = vals
                if len(vals) == 1:
                    schema["default"] = vals[0]
                    p["required"] = False
                    _param_note(p, f"faqat `{vals[0]}` (yuborilmasa avtomatik qo'yiladi)")
                else:
                    p["required"] = True
                    _param_note(p, "faqat ruxsat etilgan qiymatlar: " + ", ".join(f"`{v}`" for v in vals))
            if name == "limit" and perm.max_limit:
                schema["maximum"] = perm.max_limit
                _param_note(p, f"maksimal {perm.max_limit}")
            out.append(p)
        op["parameters"] = out

        notes = []
        hidden = list(perm.hidden_fields or [])
        if not (perm.allow_personal and client.allow_personal_data):
            hidden += PERSONAL_FIELDS
        if hidden:
            notes.append("Javobdan yashiriladigan maydonlar: " + ", ".join(f"`{h}`" for h in sorted(set(hidden))))
        if scope_map:
            notes.append("Ma'lumot doirasi: " + "; ".join(f"{SCOPE_KEYS[k]} = {', '.join(scope[k])}" for k in scope_map))
        if ep.auth_mode == "passthrough":
            notes.append("`Authorization: Bearer <talaba/tutor tokeni>` ham kerak (auth/login orqali olinadi)")
        if notes:
            op["description"] = ((op.get("description") or "") + "\n\n---\n" + "\n\n".join(notes)).strip()

        op["security"] = [{"gatewayKey": [], "userBearer": []}] if ep.auth_mode == "passthrough" else [{"gatewayKey": []}]
        if ep.upstream == "fast":
            op["servers"] = [{"url": base_url + "/fast", "description": "Fast API (gateway)"}]
        op.pop("x-codeSamples", None)
        used_tags.update(op.get("tags") or [])
        paths.setdefault(ep.path, {})[ep.method.lower()] = op

    tags = [t for t in raw.get("tags", []) if t.get("name") in used_tags]
    tags += [{"name": t} for t in sorted(used_tags - {t.get("name") for t in tags})]
    comps = copy.deepcopy(raw.get("components", {}))
    comps["securitySchemes"] = {
        "gatewayKey": {"type": "apiKey", "in": "header", "name": "X-Gateway-Key",
                       "description": "Administrator bergan gateway kaliti (hg_…)"},
        "userBearer": {"type": "http", "scheme": "bearer",
                       "description": "Talaba yoki tutor JWT tokeni (Student/Tutor API uchun)"},
    }
    limits = []
    if getattr(client, "rate_per_second", 0):
        limits.append(f"soniyasiga **{client.rate_per_second}**")
    if client.rate_per_minute:
        limits.append(f"daqiqasiga **{client.rate_per_minute}**")
    if client.daily_quota:
        limits.append(f"kuniga **{client.daily_quota}**")
    scope_txt = "; ".join(f"{SCOPE_KEYS.get(k, k)} = {', '.join(v)}" for k, v in scope.items()) or "butun OTM"
    # Namuna uchun birinchi GET endpoint (talab qilinadigan qulflangan qiymatlar bilan)
    ex_path, ex_query = "/v1/data/student-stats", ""
    cands = sorted(paths, key=lambda x: (paths[x].get("get", {}).get("security") != [{"gatewayKey": []}], x))
    for pth in cands:
        o = paths[pth].get("get")
        if o and "{" not in pth:
            ex_path = pth
            req = [f"{p['name']}={(p.get('schema') or {}).get('enum', ['…'])[0]}" for p in o.get("parameters", [])
                   if p.get("in") == "query" and p.get("required")]
            ex_query = ("?" + "&".join(req)) if req else ""
            break
    ex_url = f"{base_url}/rest{ex_path}{ex_query}"
    passthrough = any(o.get("security") == [{"gatewayKey": [], "userBearer": []}] for v in paths.values() for o in v.values())
    desc = f"""
**{client.name}** uchun API hujjati{f" · {org_name()}" if org_name() else ""}.
Bu yerda **faqat sizga ruxsat berilgan {len(paths)} ta endpoint** va ularning ruxsat etilgan filtrlari ko'rsatilgan.

## 🚀 3 qadamda boshlash

**1. Kalitni ulang.** Sahifa tepasidagi «API kalitingiz» maydoniga administrator bergan `hg_…` kalitni kiriting
va **Ulash** tugmasini bosing (yoki pastdagi 🔓 **Authorize** tugmasi). Kalit brauzerda saqlanmaydi.

**2. Endpointni tanlang.** Ro'yxatdan kerakli endpointni oching → **Try it out** → filtrlarni to'ldiring → **Execute**.

**3. Javobni ko'ring.** Pastda server javobi, tayyor `curl` buyrug'i va so'rov manzili chiqadi — uni o'z dasturingizga ko'chiring.

## 🔑 Avtorizatsiya

Har bir so'rovga sarlavha (header) qo'shiladi:

```
X-Gateway-Key: hg_xxxxxxxxxx_xxxxxxxxxxxxxxxx
```

Backend API endpointlarida HEMIS dagi kabi `Authorization: Bearer hg_…` ham ishlaydi.
{"Talaba/tutor endpointlarida (🔒 ikkita qulf) `Authorization: Bearer <talaba tokeni>` ham kerak — u `/v1/auth/login` orqali olinadi, kalit esa `X-Gateway-Key` da qoladi." if passthrough else ""}

<details>
<summary><b>💻 Kod namunalari (cURL, Python, JavaScript, PHP)</b> — bosib oching</summary>

**cURL**
```bash
curl -H "X-Gateway-Key: $KALIT" "{ex_url}"
```

**Python**
```python
import requests
r = requests.get("{base_url}/rest{ex_path}",
                 params={{{", ".join(f'"{q.split("=")[0]}": "{q.split("=")[1]}"' for q in ex_query.lstrip("?").split("&") if q)}}},
                 headers={{"X-Gateway-Key": KALIT}}, timeout=30)
print(r.json())
```

**JavaScript (server, Node.js)**
```javascript
const r = await fetch("{ex_url}", {{ headers: {{ "X-Gateway-Key": process.env.KALIT }} }});
console.log(await r.json());
```

**PHP**
```php
$ch = curl_init("{ex_url}");
curl_setopt_array($ch, [CURLOPT_HTTPHEADER => ["X-Gateway-Key: " . getenv("KALIT")], CURLOPT_RETURNTRANSFER => true]);
echo curl_exec($ch);
```

</details>

> ⚠️ Kalitni brauzerdagi (frontend) kodga yozmang — u faqat serveringizda saqlanishi kerak.

## 📏 Sizning cheklovlaringiz

- So'rovlar limiti: {", ".join(limits) or "cheklanmagan"}
- Ma'lumot doirasi: {scope_txt}
- 🔒 **Qulflangan filtr** — faqat ro'yxatdagi qiymatlarni yuborish mumkin; bitta qiymat bo'lsa, yubormasangiz ham o'zi qo'yiladi.
- Ro'yxatda ko'rinmagan filtrlar sizga yopiq — yuborilsa `403 param_not_allowed` qaytadi.
- Shaxsiy ma'lumotlar (PINFL, pasport, telefon, manzil…) ruxsat bo'lmasa javobdan olib tashlanadi.
- `limit` — bir sahifadagi yozuvlar soni, `page` — sahifa raqami. Til: `l=uz-UZ | oz-UZ | ru-RU | en-US`. Sanalar — UTC timestamp.

<details>
<summary><b>❗ Xato kodlari va ularning ma'nosi</b> — bosib oching</summary>

| Kod | `gateway_code` (misol) | Nima qilish kerak |
|---|---|---|
| 401 | `no_key`, `invalid_key` | Kalit yuborilmagan yoki noto'g'ri — sarlavhani tekshiring |
| 403 | `endpoint_not_allowed`, `param_not_allowed`, `scope_violation`, `locked_value` | Bu endpoint/filtr/qiymat sizga ruxsat etilmagan — administratorga murojaat qiling |
| 403 | `ip_not_allowed`, `ip_blocked`, `client_suspended` | Sizning IP manzil yoki kalitingiz cheklangan |
| 410 | `endpoint_removed` | Endpoint HEMIS dan olib tashlangan |
| 429 | `rate_limited`, `rate_limited_second`, `quota_exceeded` | Limit tugadi — `Retry-After` soniyadan keyin qayta urining |
| 502–504 | `upstream_*` | HEMIS da vaqtinchalik muammo — birozdan keyin qayta urining |

Xato javobi namunasi:
```json
{{"success": false, "error": "'search' filtridan foydalanish sizga ruxsat etilmagan", "code": 403, "gateway_code": "param_not_allowed"}}
```

</details>
"""
    return {
        "openapi": raw.get("openapi", "3.0.0"),
        "info": {"title": f"{org_short() or 'HEMIS'} API Gateway", "version": raw.get("info", {}).get("version", "1.0"),
                 "description": desc + f"\n\n---\n<small>{org_name() or 'HEMIS'} · Powered by {__title__} v{__version__} · "
                                       f"{__copyright__} · {__license__}</small>",
                 "license": {"name": "HEMIS API Gateway: Apache-2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"}},
        "servers": [{"url": base_url + "/rest", "description": org_name() or "HEMIS API Gateway"}],
        "tags": tags,
        "paths": dict(sorted(paths.items())),
        "components": comps,
    }
