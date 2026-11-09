# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Boshqaruv paneli API: mijozlar, ruxsatlar, katalog, loglar, monitoring, sozlamalar, adminlar."""
import json
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .admin_auth import admin_out, audit, can_edit, can_view, is_super, ROLES
from .catalog import PERSONAL_FIELDS, SCOPE_KEYS, sync_catalog
from .db import get_db
from .kv import kv
from .models import Admin, AdminAudit, Client, Endpoint, Permission, RequestLog, Setting
from .policy import evaluate
from .security import client_ip, encrypt, generate_api_key, hash_password, password_problems
from .state import bump_version, state

router = APIRouter(prefix="/api/admin", tags=["Admin"])


def iso(d):
    if not d:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat()


# =============================== META ===============================

@router.get("/meta")
async def meta(a: Admin = Depends(can_view)):
    return {"scope_keys": SCOPE_KEYS, "personal_fields": PERSONAL_FIELDS, "roles": ROLES,
            "auth_modes": {"admin": "Gateway admin tokeni", "passthrough": "Mijoz tokeni (talaba/tutor)",
                           "public": "Ochiq", "fast": "Fast API token"}}


# =============================== MIJOZLAR ===============================

class ClientIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    description: str = ""
    contact: str = ""
    is_active: bool = True
    expires_at: datetime | None = None
    allowed_ips: list[str] = []
    allowed_origins: list[str] = []
    rate_per_second: int = Field(10, ge=0, le=1000)
    rate_per_minute: int = Field(60, ge=0, le=100000)
    daily_quota: int = Field(10000, ge=0, le=100000000)
    scope: dict[str, list[str]] = {}
    strict_scope: bool = True
    allow_personal_data: bool = False
    docs_username: str | None = Field(None, max_length=64)
    docs_enabled: bool = True
    max_distinct_ips: int | None = Field(None, ge=0, le=100000)


DOCS_LOGIN_RE = re.compile(r"^[a-z0-9_.\-]{3,64}$")


def _slug(name: str) -> str:
    tr = str.maketrans({"ʻ": "", "ʼ": "", "'": "", "‘": "", "’": "", "`": ""})
    s = re.sub(r"[^a-z0-9]+", "_", name.lower().translate(tr)).strip("_")[:24]
    return s if len(s) >= 3 else "client"


def gen_docs_password() -> str:
    import secrets
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(14))
        if any(c.isdigit() for c in pw) and any(c.isalpha() for c in pw):
            return pw


async def _docs_username(db: AsyncSession, wanted: str | None, name: str, exclude_id: int | None = None) -> str:
    import secrets
    if wanted:
        u = wanted.strip().lower()
        if not DOCS_LOGIN_RE.match(u):
            raise HTTPException(400, "Docs login: 3–64 belgi, faqat lotin harflari, raqam, _ . -")
        q = select(Client.id).where(Client.docs_username == u)
        if exclude_id:
            q = q.where(Client.id != exclude_id)
        if (await db.execute(q)).first():
            raise HTTPException(400, f"'{u}' docs logini band")
        return u
    base = _slug(name)
    for _ in range(20):
        u = f"{base}_{secrets.token_hex(2)}"
        if not (await db.execute(select(Client.id).where(Client.docs_username == u))).first():
            return u
    raise HTTPException(500, "Login yaratib bo'lmadi")


def _clean_client(data: ClientIn) -> dict:
    import ipaddress
    d = data.model_dump()
    for ip in d["allowed_ips"]:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            raise HTTPException(400, f"Noto'g'ri IP: {ip}")
    for o in d["allowed_origins"]:
        if not (o.startswith("https://") or o.startswith("http://")) or o.endswith("/"):
            raise HTTPException(400, f"Origin formati: https://domen.uz  ({o})")
    sc = {}
    for k, v in d["scope"].items():
        if k not in SCOPE_KEYS:
            raise HTTPException(400, f"Noma'lum doira kaliti: {k}")
        vals = [str(x).strip() for x in v if str(x).strip()]
        if vals:
            sc[k] = vals
    d["scope"] = sc
    d.pop("docs_username", None)
    return d


def client_out(c: Client, extra: dict | None = None) -> dict:
    out = {"id": c.id, "name": c.name, "description": c.description, "contact": c.contact,
           "key_prefix": c.key_prefix, "is_active": c.is_active, "expires_at": iso(c.expires_at),
           "allowed_ips": c.allowed_ips, "allowed_origins": c.allowed_origins,
           "rate_per_second": c.rate_per_second, "rate_per_minute": c.rate_per_minute, "daily_quota": c.daily_quota, "scope": c.scope,
           "strict_scope": c.strict_scope, "allow_personal_data": c.allow_personal_data,
           "created_at": iso(c.created_at), "created_by": c.created_by, "last_used_at": iso(c.last_used_at),
           "key_rotated_at": iso(c.key_rotated_at), "docs_username": c.docs_username,
           "docs_enabled": c.docs_enabled, "docs_password_set": bool(c.docs_password_hash),
           "docs_last_login_at": iso(c.docs_last_login_at), "suspended_until": iso(c.suspended_until),
           "suspend_reason": c.suspend_reason, "max_distinct_ips": c.max_distinct_ips}
    if extra:
        out.update(extra)
    return out


@router.get("/clients")
async def list_clients(a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    pc = dict((await db.execute(select(Permission.client_id, func.count()).group_by(Permission.client_id))).all())
    rq = {r[0]: (r[1], r[2]) for r in (await db.execute(
        select(RequestLog.client_id, func.count(), func.sum(case((RequestLog.status >= 400, 1), else_=0)))
        .where(RequestLog.ts >= since).group_by(RequestLog.client_id))).all()}
    cs = (await db.execute(select(Client).order_by(Client.id))).scalars().all()
    return [client_out(c, {"permissions_count": pc.get(c.id, 0), "requests_24h": rq.get(c.id, (0, 0))[0],
                           "errors_24h": int(rq.get(c.id, (0, 0))[1] or 0)}) for c in cs]


@router.post("/clients")
async def create_client(data: ClientIn, request: Request, a: Admin = Depends(can_edit), db: AsyncSession = Depends(get_db)):
    full, prefix, h = generate_api_key()
    docs_user = await _docs_username(db, data.docs_username, data.name)
    docs_pw = gen_docs_password()
    c = Client(**_clean_client(data), key_prefix=prefix, key_hash=h, created_by=a.username,
               docs_username=docs_user, docs_password_hash=hash_password(docs_pw))
    db.add(c)
    await db.flush()
    await audit(db, a.username, "client_create", f"client:{c.id}", {"name": c.name, "docs": docs_user}, client_ip(request))
    await db.commit()
    await bump_version()
    return {"client": client_out(c), "api_key": full, "docs_username": docs_user, "docs_password": docs_pw}


@router.get("/clients/{cid}")
async def get_client(cid: int, a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db)):
    c = (await db.execute(select(Client).where(Client.id == cid).options(selectinload(Client.permissions)))).scalar_one_or_none()
    if not c:
        raise HTTPException(404, "Mijoz topilmadi")
    perms = [{"endpoint_id": p.endpoint_id, "allowed_params": p.allowed_params, "locked_params": p.locked_params,
              "max_limit": p.max_limit, "hidden_fields": p.hidden_fields, "allow_personal": p.allow_personal}
             for p in c.permissions]
    return client_out(c, {"permissions": perms})


@router.put("/clients/{cid}")
async def update_client(cid: int, data: ClientIn, request: Request, a: Admin = Depends(can_edit),
                        db: AsyncSession = Depends(get_db)):
    c = await db.get(Client, cid)
    if not c:
        raise HTTPException(404, "Mijoz topilmadi")
    d = _clean_client(data)
    if data.docs_username and data.docs_username.strip().lower() != c.docs_username:
        d["docs_username"] = await _docs_username(db, data.docs_username, c.name, exclude_id=c.id)
    changes = {k: v for k, v in d.items() if getattr(c, k) != v}
    if "docs_username" in changes or "docs_enabled" in changes or "is_active" in changes:
        c.docs_token_version += 1   # ochiq docs sessiyalarini bekor qilish
    for k, v in d.items():
        setattr(c, k, v)
    await audit(db, a.username, "client_update", f"client:{c.id}", json.loads(json.dumps(changes, default=str)),
                client_ip(request))
    await db.commit()
    await bump_version()
    return client_out(c)


@router.delete("/clients/{cid}")
async def delete_client(cid: int, request: Request, a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    c = await db.get(Client, cid)
    if not c:
        raise HTTPException(404, "Mijoz topilmadi")
    await db.execute(delete(Permission).where(Permission.client_id == cid))
    await db.delete(c)
    await audit(db, a.username, "client_delete", f"client:{cid}", {"name": c.name}, client_ip(request))
    await db.commit()
    await bump_version()
    return {"ok": True}


@router.post("/clients/{cid}/rotate-key")
async def rotate_key(cid: int, request: Request, a: Admin = Depends(can_edit), db: AsyncSession = Depends(get_db)):
    c = await db.get(Client, cid)
    if not c:
        raise HTTPException(404, "Mijoz topilmadi")
    full, prefix, h = generate_api_key()
    c.key_prefix, c.key_hash, c.key_rotated_at = prefix, h, datetime.now(timezone.utc)
    await audit(db, a.username, "client_rotate_key", f"client:{cid}", {}, client_ip(request))
    await db.commit()
    await bump_version()
    return {"api_key": full, "key_prefix": prefix}


@router.post("/clients/{cid}/docs-password")
async def reset_docs_password(cid: int, request: Request, a: Admin = Depends(can_edit), db: AsyncSession = Depends(get_db)):
    c = await db.get(Client, cid)
    if not c:
        raise HTTPException(404, "Mijoz topilmadi")
    if not c.docs_username:
        c.docs_username = await _docs_username(db, None, c.name)
    pw = gen_docs_password()
    c.docs_password_hash = hash_password(pw)
    c.docs_token_version += 1
    await audit(db, a.username, "client_docs_password", f"client:{cid}", {"docs": c.docs_username}, client_ip(request))
    await db.commit()
    return {"docs_username": c.docs_username, "docs_password": pw}


class PermIn(BaseModel):
    endpoint_id: int
    allowed_params: list[str] | None = None
    locked_params: dict[str, list[str]] = {}
    max_limit: int | None = Field(None, ge=1, le=200)
    hidden_fields: list[str] = []
    allow_personal: bool = False


@router.put("/clients/{cid}/permissions")
async def set_permissions(cid: int, perms: list[PermIn], request: Request, a: Admin = Depends(can_edit),
                          db: AsyncSession = Depends(get_db)):
    c = await db.get(Client, cid)
    if not c:
        raise HTTPException(404, "Mijoz topilmadi")
    eps = {e.id: e for e in (await db.execute(select(Endpoint))).scalars()}
    old = {p.endpoint_id: p for p in (await db.execute(select(Permission).where(Permission.client_id == cid))).scalars()}
    new_ids = set()
    for p in perms:
        e = eps.get(p.endpoint_id)
        if not e:
            raise HTTPException(400, f"Endpoint #{p.endpoint_id} topilmadi")
        names = {x["name"] for x in e.params}
        if p.allowed_params is not None:
            bad = set(p.allowed_params) - names - {"l"}
            if bad:
                raise HTTPException(400, f"{e.path}: hujjatda yo'q filtr(lar): {', '.join(sorted(bad))}")
        locked = {}
        for k, v in p.locked_params.items():
            if k not in names:
                raise HTTPException(400, f"{e.path}: qulflanadigan filtr hujjatda yo'q: {k}")
            vals = [str(x).strip() for x in v if str(x).strip()]
            if vals:
                locked[k] = vals
        hidden = [h.strip() for h in p.hidden_fields if h.strip()]
        new_ids.add(e.id)
        row = old.get(e.id)
        if row is None:
            row = Permission(client_id=cid, endpoint_id=e.id)
            db.add(row)
        row.allowed_params, row.locked_params, row.max_limit = p.allowed_params, locked, p.max_limit
        row.hidden_fields, row.allow_personal = hidden, p.allow_personal
    removed = [eid for eid in old if eid not in new_ids]
    for eid in removed:
        await db.delete(old[eid])
    await audit(db, a.username, "permissions_set", f"client:{cid}",
                {"count": len(new_ids), "added": len(new_ids - set(old)), "removed": len(removed)}, client_ip(request))
    await db.commit()
    await bump_version()
    return {"ok": True, "count": len(new_ids)}


@router.post("/clients/{cid}/copy-from/{src}")
async def copy_permissions(cid: int, src: int, request: Request, a: Admin = Depends(can_edit),
                           db: AsyncSession = Depends(get_db)):
    if cid == src:
        raise HTTPException(400, "Bir xil mijoz")
    srcp = (await db.execute(select(Permission).where(Permission.client_id == src))).scalars().all()
    await db.execute(delete(Permission).where(Permission.client_id == cid))
    for p in srcp:
        db.add(Permission(client_id=cid, endpoint_id=p.endpoint_id, allowed_params=p.allowed_params,
                          locked_params=p.locked_params, max_limit=p.max_limit, hidden_fields=p.hidden_fields,
                          allow_personal=p.allow_personal))
    await audit(db, a.username, "permissions_copy", f"client:{cid}", {"from": src}, client_ip(request))
    await db.commit()
    await bump_version()
    return {"ok": True, "count": len(srcp)}


class SimIn(BaseModel):
    method: str = "GET"
    url: str  # masalan: /rest/v1/data/student-list?_department=7&limit=50


@router.post("/clients/{cid}/simulate")
async def simulate(cid: int, data: SimIn, a: Admin = Depends(can_view)):
    """HEMIS ga so'rov yubormasdan: shu mijoz so'rovi o'tadimi va HEMIS ga qanday ketadi."""
    await state.ensure_fresh()
    c = next((x for x in state.clients.values() if x.id == cid), None)
    if not c:
        raise HTTPException(404, "Mijoz topilmadi")
    url = data.url.strip()
    for pre in ("https://", "http://"):
        if url.startswith(pre):
            url = "/" + url[len(pre):].split("/", 1)[-1]
    path, _, qs = url.partition("?")
    if path.startswith("/rest/"):
        upstream, p = "hemis", path[5:]
    elif path.startswith("/fast/"):
        upstream, p = "fast", path[5:]
    else:
        upstream, p = "hemis", path
    eid, pp = state.router.match(upstream, data.method.upper(), p)
    ep = state.endpoints.get(eid) if eid else None
    if not ep:
        return {"ok": False, "code": "unknown_endpoint", "message": "Endpoint katalogda yo'q"}
    d = evaluate(ep, c.perms.get(ep.id), c, parse_qsl(qs, keep_blank_values=True), pp)
    from urllib.parse import urlencode
    return {"ok": d.ok, "code": d.code, "message": d.message, "endpoint": {"id": ep.id, "path": ep.path,
            "auth_mode": ep.auth_mode}, "upstream_query": urlencode(d.query) if d.ok else None,
            "hidden_fields": d.hidden_fields if d.ok else None}


# =============================== ENDPOINTLAR ===============================

def ep_out(e: Endpoint, perm_counts: dict | None = None) -> dict:
    return {"id": e.id, "method": e.method, "path": e.path, "upstream": e.upstream, "group": e.group,
            "summary": e.summary, "description": e.description, "auth_mode": e.auth_mode, "params": e.params,
            "has_body": e.has_body, "is_enabled": e.is_enabled, "in_spec": e.in_spec,
            "removed_at": iso(e.removed_at), "risk": e.risk, "cache_ttl": e.cache_ttl,
            "clients": (perm_counts or {}).get(e.id, 0)}


@router.get("/endpoints")
async def list_endpoints(a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db)):
    pc = dict((await db.execute(select(Permission.endpoint_id, func.count()).group_by(Permission.endpoint_id))).all())
    es = (await db.execute(select(Endpoint).order_by(Endpoint.group, Endpoint.path))).scalars().all()
    return [ep_out(e, pc) for e in es]


class EndpointIn(BaseModel):
    is_enabled: bool
    auth_mode: str
    cache_ttl: int = Field(ge=0, le=86400)
    risk: str
    scope_map: dict[str, str | None] = {}  # param -> scope_key


@router.put("/endpoints/{eid}")
async def update_endpoint(eid: int, data: EndpointIn, request: Request, a: Admin = Depends(is_super),
                          db: AsyncSession = Depends(get_db)):
    e = await db.get(Endpoint, eid)
    if not e:
        raise HTTPException(404, "Topilmadi")
    if data.auth_mode not in ("admin", "passthrough", "public", "fast") or data.risk not in ("low", "medium", "high"):
        raise HTTPException(400, "Noto'g'ri qiymat")
    params = []
    for p in e.params:
        p = dict(p)
        if p["name"] in data.scope_map:
            sk = data.scope_map[p["name"]] or None
            if sk and sk not in SCOPE_KEYS:
                raise HTTPException(400, f"Noma'lum doira: {sk}")
            p["scope_key"] = sk
        params.append(p)
    e.is_enabled, e.auth_mode, e.cache_ttl, e.risk, e.params = data.is_enabled, data.auth_mode, data.cache_ttl, data.risk, params
    await audit(db, a.username, "endpoint_update", f"{e.method} {e.path}", data.model_dump(), client_ip(request))
    await db.commit()
    await bump_version()
    return ep_out(e)


@router.post("/endpoints/sync")
async def sync_endpoints(request: Request, file: UploadFile | None = None, a: Admin = Depends(is_super),
                         db: AsyncSession = Depends(get_db)):
    spec = None
    if file is not None:
        raw = await file.read()
        if len(raw) > 20 * 1024 * 1024:
            raise HTTPException(400, "Fayl juda katta")
        try:
            spec = json.loads(raw)
            assert "paths" in spec
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "OpenAPI JSON fayli noto'g'ri")
    if spec is None:
        from .config import settings as _s
        if not Path(_s.OPENAPI_PATH).exists():
            raise HTTPException(400, "HEMIS hujjati hali sinxronlanmagan — Sozlamalar → «Saqlash va sinxronlash»")
        raw = Path(_s.OPENAPI_PATH).read_bytes()
        spec = json.loads(raw)
    from .spec_update import apply_spec
    res = await apply_spec(db, spec, raw)
    await audit(db, a.username, "catalog_sync", "", res, client_ip(request))
    await db.commit()
    await bump_version()
    return res


@router.post("/cache/clear")
async def clear_cache(request: Request, a: Admin = Depends(can_edit), db: AsyncSession = Depends(get_db)):
    n = await kv.delete_prefix("cache:")
    await kv.delete_prefix("stats:")
    await audit(db, a.username, "cache_clear", "", {"keys": n}, client_ip(request))
    await db.commit()
    return {"ok": True, "deleted": n}


# =============================== LOGLAR ===============================

@router.get("/logs")
async def logs(a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db), client_id: int | None = None,
               status: str | None = None, path: str | None = None, ip: str | None = None,
               date_from: datetime | None = None, date_to: datetime | None = None, page: int = 1, limit: int = 50):
    limit = max(1, min(limit, 200))
    q = select(RequestLog)
    if client_id:
        q = q.where(RequestLog.client_id == client_id)
    if status == "ok":
        q = q.where(RequestLog.status < 400)
    elif status == "denied":
        q = q.where(RequestLog.status.in_([401, 403, 429]))
    elif status == "error":
        q = q.where(RequestLog.status >= 500)
    elif status and status.isdigit():
        q = q.where(RequestLog.status == int(status))
    if path:
        q = q.where(RequestLog.path.contains(path))
    if ip:
        q = q.where(RequestLog.ip == ip)
    if date_from:
        q = q.where(RequestLog.ts >= date_from)
    if date_to:
        q = q.where(RequestLog.ts <= date_to)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await db.execute(q.order_by(RequestLog.id.desc()).offset((page - 1) * limit).limit(limit))).scalars().all()
    return {"total": total, "page": page, "items": [
        {"id": r.id, "ts": iso(r.ts), "client_id": r.client_id, "client_name": r.client_name, "method": r.method,
         "path": r.path, "query": r.query, "status": r.status, "upstream_status": r.upstream_status,
         "latency_ms": r.latency_ms, "bytes": r.bytes, "ip": r.ip, "user_agent": r.user_agent,
         "cache_hit": r.cache_hit, "denied_reason": r.denied_reason, "detail": r.detail} for r in rows]}


@router.get("/audit")
async def audit_log(a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db), page: int = 1, limit: int = 50):
    limit = max(1, min(limit, 200))
    total = (await db.execute(select(func.count(AdminAudit.id)))).scalar()
    rows = (await db.execute(select(AdminAudit).order_by(AdminAudit.id.desc()).offset((page - 1) * limit).limit(limit))).scalars()
    return {"total": total, "items": [{"id": r.id, "ts": iso(r.ts), "admin": r.admin, "action": r.action,
                                       "target": r.target, "details": r.details, "ip": r.ip} for r in rows]}


# =============================== MONITORING ===============================

@router.get("/monitor/summary")
async def monitor(a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db), hours: int = 24):
    hours = max(1, min(hours, 24 * 90))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    base = select(RequestLog).where(RequestLog.ts >= since).subquery()
    R = base.c
    tot = (await db.execute(select(
        func.count(), func.sum(case((R.status < 400, 1), else_=0)),
        func.sum(case((R.status.in_([401, 403, 429]), 1), else_=0)),
        func.sum(case((R.status >= 500, 1), else_=0)),
        func.avg(R.latency_ms), func.sum(case((R.cache_hit.is_(True), 1), else_=0)), func.sum(R.bytes),
        func.count(func.distinct(R.client_id))))).one()
    total = tot[0] or 0

    # vaqt bo'yicha (python tomonda guruhlash — Postgres va SQLite uchun bir xil ishlaydi)
    bucket = 3600 if hours <= 72 else 86400
    kind = case((R.status < 400, 0), (R.status.in_([401, 403, 429]), 1), else_=2)
    series: dict[int, list[int]] = {}
    if db.bind.dialect.name == "postgresql":
        tb = func.date_trunc("hour" if bucket == 3600 else "day", R.ts)
        rows = (await db.execute(select(tb, kind, func.count()).group_by(tb, kind))).all()
        for ts, k, n in rows:
            b = int(ts.replace(tzinfo=ts.tzinfo or timezone.utc).timestamp() // bucket * bucket)
            series.setdefault(b, [0, 0, 0])[k] += n
    else:
        for ts, k in (await db.execute(select(R.ts, kind))).all():
            b = int(ts.replace(tzinfo=ts.tzinfo or timezone.utc).timestamp() // bucket * bucket)
            series.setdefault(b, [0, 0, 0])[k] += 1
    start = int(since.timestamp() // bucket * bucket)
    now_b = int(datetime.now(timezone.utc).timestamp() // bucket * bucket)
    ser = [{"t": datetime.fromtimestamp(b, timezone.utc).isoformat(), "ok": series.get(b, [0, 0, 0])[0],
            "denied": series.get(b, [0, 0, 0])[1], "error": series.get(b, [0, 0, 0])[2]}
           for b in range(start, now_b + 1, bucket)]

    top_clients = [{"client_id": r[0], "name": r[1], "count": r[2], "denied": int(r[3] or 0)} for r in (await db.execute(
        select(R.client_id, R.client_name, func.count(), func.sum(case((R.status >= 400, 1), else_=0)))
        .where(R.client_id.is_not(None)).group_by(R.client_id, R.client_name).order_by(func.count().desc()).limit(10))).all()]
    top_paths = [{"path": r[0], "count": r[1], "avg_ms": round(r[2] or 0, 1)} for r in (await db.execute(
        select(R.path, func.count(), func.avg(R.latency_ms)).group_by(R.path).order_by(func.count().desc()).limit(10))).all()]
    reasons = [{"reason": r[0], "count": r[1]} for r in (await db.execute(
        select(R.denied_reason, func.count()).where(R.denied_reason != "").group_by(R.denied_reason)
        .order_by(func.count().desc()).limit(12))).all()]
    top_ips = [{"ip": r[0], "count": r[1]} for r in (await db.execute(
        select(R.ip, func.count()).where(R.status.in_([401, 403, 429])).group_by(R.ip)
        .order_by(func.count().desc()).limit(8))).all()]

    try:
        await kv.ping()
        kv_ok = True
    except Exception:  # noqa: BLE001
        kv_ok = False
    await state.ensure_fresh()
    return {"hours": hours, "total": total, "ok": int(tot[1] or 0), "denied": int(tot[2] or 0), "errors": int(tot[3] or 0),
            "avg_latency_ms": round(tot[4] or 0, 1), "cache_hits": int(tot[5] or 0), "bytes": int(tot[6] or 0),
            "active_clients": tot[7] or 0, "series": ser, "bucket": bucket, "top_clients": top_clients,
            "top_paths": top_paths, "deny_reasons": reasons, "suspicious_ips": top_ips,
            "system": {"kv": kv_ok, "hemis_token": bool(state.hemis_token), "hemis_base": state.hemis_base,
                       "clients": len(state.clients), "endpoints": len(state.endpoints)}}


# =============================== SOZLAMALAR ===============================

SETTING_KEYS = {
    "hemis_base_url": False, "hemis_admin_token": True, "fast_api_url": False, "fast_api_token": True,
    "org_name": False, "org_short": False, "public_base_url": False,
}


@router.get("/settings")
async def get_settings_(a: Admin = Depends(is_super)):
    await state.ensure_fresh()
    from .branding import org_name, org_short, logo_path
    return {"hemis_base_url": state.hemis_base, "fast_api_url": state.fast_base,
            "org_name": org_name(), "org_short": state.settings.get("org_short", ""), "org_short_auto": org_short(),
            "public_base_url": state.settings.get("public_base_url", ""), "has_logo": logo_path() is not None,
            "hemis_admin_token_set": bool(state.hemis_token),
            "secret_errors": sorted(state.secret_errors),
            "docs_password_set": bool(state.settings.get("spec_password")),
            "hemis_admin_token_hint": ("…" + state.hemis_token[-4:]) if state.hemis_token else "",
            "fast_api_token_set": bool(state.fast_token)}


@router.put("/settings")
async def put_settings(data: dict, request: Request, a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    changed = []
    for k, v in data.items():
        if k not in SETTING_KEYS or v is None:
            continue
        v = str(v).strip()
        if k == "hemis_base_url" and v:
            from .branding import normalize_hemis_base
            v = normalize_hemis_base(v)
        if k in ("hemis_admin_token", "fast_api_token") and v:
            from .branding import clean_token
            v = clean_token(v)
        if k.endswith("_url") and v and not v.startswith("https://") and not v.startswith("http://"):
            raise HTTPException(400, f"{k}: URL noto'g'ri")
        if k in ("org_name", "org_short") and len(v) > 200:
            raise HTTPException(400, f"{k}: juda uzun")
        secret = SETTING_KEYS[k]
        row = await db.get(Setting, k)
        if row is None:
            row = Setting(key=k)
            db.add(row)
        row.value, row.is_secret = (encrypt(v) if secret else v), secret
        changed.append(k)
    await audit(db, a.username, "settings_update", "", {"keys": changed}, client_ip(request))
    await db.commit()
    await bump_version()
    return {"ok": True, "changed": changed}


@router.post("/settings/test")
async def test_upstream(data: dict | None = None, a: Admin = Depends(is_super)):
    """Ulanishni tekshirish. Formadagi hali saqlanmagan manzil/token bilan ham ishlaydi."""
    from .branding import clean_token, fetch_university_profile, normalize_hemis_base
    from .config import settings as _s
    from .upstream import http
    await state.ensure_fresh()
    data = data or {}
    base = normalize_hemis_base(data.get("hemis_base_url") or "") or state.hemis_base
    form_token = clean_token(data.get("hemis_admin_token") or "")
    token = form_token or state.hemis_token
    if form_token:
        source = "formadagi (hali saqlanmagan) token"
    elif state.settings.get("hemis_admin_token"):
        source = "panelda saqlangan token"
    elif _s.HEMIS_ADMIN_TOKEN:
        source = ".env dagi HEMIS_ADMIN_TOKEN"
    else:
        source = ""
    diag = {"base": base, "token_source": source, "token_hint": (f"…{token[-4:]} ({len(token)} belgi)" if token else "")}
    if not base:
        return {"ok": False, "status": None, "body": "HEMIS manzili kiritilmagan", "diag": diag}
    if "hemis_admin_token" in state.secret_errors and not form_token:
        return {"ok": False, "status": None, "diag": diag,
                "body": "Saqlangan tokenni ochib bo'lmadi: server kaliti (ENCRYPTION_KEY/SECRET_KEY) o'zgargan. Tokenni qayta kiriting va saqlang.",
                "hint": "Tokenni qayta kiriting"}
    if not token:
        return {"ok": False, "status": None, "body": "Token kiritilmagan", "diag": diag}
    profile = await fetch_university_profile(save=True) if base == state.hemis_base else None
    if profile and profile.get("name") and not state.settings.get("org_name"):
        from .db import SessionLocal
        async with SessionLocal() as db:
            for k, v in (("org_name", profile["name"]), ("org_code", profile.get("code", ""))):
                row = await db.get(Setting, k) or Setting(key=k)
                row.value = v
                db.add(row)
            await db.commit()
        await bump_version()
    try:
        r = await http().get(base + "/v1/data/version-info",
                             headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        body = r.json() if "json" in r.headers.get("content-type", "") else r.text[:300]
        ok = r.status_code == 200
        hint = ""
        if r.status_code in (401, 403):
            hint = ("HEMIS tokenni qabul qilmadi. Tekshiring: 1) token HEMIS admin panelidan to'liq nusxalanganmi "
                    f"(oxiri {diag['token_hint'] or '—'}); 2) token egasi foydalanuvchida «API User» roli bormi; "
                    "3) token keyinroq qayta yaratilmaganmi (eski token bekor bo'ladi)"
                    + ("; 4) formadagi tokenni «Saqlash» tugmasi bilan saqlang" if form_token else ""))
        if ok and form_token:
            hint = "Token to'g'ri — «Saqlash» tugmasini bosishni unutmang"
        return {"ok": ok, "status": r.status_code, "body": body, "profile": profile, "hint": hint, "diag": diag}
    except Exception as ex:  # noqa: BLE001
        return {"ok": False, "status": None, "body": str(ex)[:300], "profile": profile, "diag": diag}


# =============================== ADMINLAR ===============================

class AdminIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.\-]+$")
    full_name: str = ""
    role: str = "admin"
    is_active: bool = True
    password: str | None = None


@router.get("/admins")
async def list_admins(a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    return [admin_out(x) for x in (await db.execute(select(Admin).order_by(Admin.id))).scalars()]


@router.post("/admins")
async def create_admin(data: AdminIn, request: Request, a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    if data.role not in ROLES:
        raise HTTPException(400, "Noto'g'ri rol")
    if not data.password or (p := password_problems(data.password)):
        raise HTTPException(400, p if data.password else "Parol kiriting")
    if (await db.execute(select(Admin).where(Admin.username == data.username))).first():
        raise HTTPException(400, "Bunday login mavjud")
    x = Admin(username=data.username, full_name=data.full_name, role=data.role, is_active=data.is_active,
              password_hash=hash_password(data.password))
    db.add(x)
    await audit(db, a.username, "admin_create", data.username, {"role": data.role}, client_ip(request))
    await db.commit()
    return admin_out(x)


@router.put("/admins/{aid}")
async def update_admin(aid: int, data: AdminIn, request: Request, a: Admin = Depends(is_super),
                       db: AsyncSession = Depends(get_db)):
    x = await db.get(Admin, aid)
    if not x:
        raise HTTPException(404, "Topilmadi")
    if data.role not in ROLES:
        raise HTTPException(400, "Noto'g'ri rol")
    if x.id == a.id and (data.role != "superadmin" or not data.is_active):
        raise HTTPException(400, "O'zingizning rolingiz/holatingizni o'zgartira olmaysiz")
    x.full_name, x.role, x.is_active = data.full_name, data.role, data.is_active
    if data.password:
        if (p := password_problems(data.password)):
            raise HTTPException(400, p)
        x.password_hash = hash_password(data.password)
        x.totp_secret = None if data.password else x.totp_secret
    x.token_version += 1
    await audit(db, a.username, "admin_update", x.username, {"role": data.role, "active": data.is_active,
                                                             "password_reset": bool(data.password)}, client_ip(request))
    await db.commit()
    return admin_out(x)


@router.delete("/admins/{aid}")
async def delete_admin(aid: int, request: Request, a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    x = await db.get(Admin, aid)
    if not x or x.id == a.id:
        raise HTTPException(400, "O'chirib bo'lmaydi")
    await db.delete(x)
    await audit(db, a.username, "admin_delete", x.username, {}, client_ip(request))
    await db.commit()
    return {"ok": True}
