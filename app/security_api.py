# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Panel API: IP qoidalari, avtomatik himoya sozlamalari, Telegram, xavfsizlik hodisalari."""
import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import guard
from .admin_auth import audit, can_edit, can_view, is_super
from .db import SessionLocal, get_db
from .models import Admin, Client, IpRule, RequestLog, SecurityEvent, Setting
from .security import client_ip, encrypt
from .state import bump_version, state

router = APIRouter(prefix="/api/admin/security", tags=["Xavfsizlik"])


def iso(d):
    if not d:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat()


def _active(r) -> bool:
    return not r.expires_at or guard._aware(r.expires_at) > datetime.now(timezone.utc)


@router.get("/rules")
async def rules(a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db)):
    rs = (await db.execute(select(IpRule).order_by(IpRule.id.desc()))).scalars().all()
    return [{"id": r.id, "cidr": r.cidr, "action": r.action, "area": r.area, "reason": r.reason, "auto": r.auto,
             "expires_at": iso(r.expires_at), "created_by": r.created_by, "created_at": iso(r.created_at),
             "active": _active(r)} for r in rs]


class RuleIn(BaseModel):
    cidr: str = Field(min_length=3, max_length=64)
    action: str = "block"
    area: str = "all"
    minutes: int = Field(0, ge=0, le=10 * 365 * 24 * 60)  # 0 = doimiy
    reason: str = ""


@router.post("/rules")
async def add_rule(data: RuleIn, request: Request, a: Admin = Depends(can_edit), db: AsyncSession = Depends(get_db)):
    try:
        net = ipaddress.ip_network(data.cidr.strip(), strict=False)
    except ValueError:
        raise HTTPException(400, "IP yoki CIDR noto'g'ri (masalan 1.2.3.4 yoki 10.0.0.0/24)")
    if data.action not in ("block", "allow") or data.area not in guard.AREAS:
        raise HTTPException(400, "Noto'g'ri qiymat")
    me = client_ip(request)
    if data.action == "block" and data.area in ("all", "admin"):
        try:
            if ipaddress.ip_address(me) in net:
                raise HTTPException(400, f"O'zingizning IP manzilingizni ({me}) bloklay olmaysiz")
        except ValueError:
            pass
    if net.prefixlen < (8 if net.version == 4 else 32):
        raise HTTPException(400, "Juda keng diapazon")
    if data.action == "block":
        r = await guard.ban_ip(str(net), data.minutes * 60 or None, data.reason or "qo'lda bloklandi", auto=False,
                               by=a.username, area=data.area)
    else:
        cidr = str(net.network_address) if net.num_addresses == 1 else str(net)
        r = IpRule(cidr=cidr, action="allow", area=data.area, reason=data.reason[:256], auto=False,
                   expires_at=datetime.now(timezone.utc) + timedelta(minutes=data.minutes) if data.minutes else None,
                   created_by=a.username)
        db.add(r)
        await db.commit()
        await guard.kv.delete(f"ban:{cidr}")
        await bump_version()
    await audit(db, a.username, f"ip_{data.action}", str(net), {"area": data.area, "minutes": data.minutes,
                                                                "reason": data.reason}, me)
    await db.commit()
    return {"ok": True, "id": r.id}


@router.delete("/rules/{rid}")
async def del_rule(rid: int, request: Request, a: Admin = Depends(can_edit), db: AsyncSession = Depends(get_db)):
    r = await db.get(IpRule, rid)
    if not r:
        raise HTTPException(404, "Topilmadi")
    cidr, action = r.cidr, r.action
    await db.close()
    await guard.unban(rid, a.username)
    async with SessionLocal() as db2:
        await audit(db2, a.username, "ip_rule_delete", cidr, {"action": action}, client_ip(request))
        await db2.commit()
    return {"ok": True}


@router.get("/settings")
async def get_sec(a: Admin = Depends(can_view)):
    await state.ensure_fresh()
    out = {k: guard.sec(k) for k in guard.SEC_DEFAULTS if k not in guard.SEC_SECRET}
    out["telegram_bot_token_set"] = bool(guard.sec("telegram_bot_token"))
    out["defaults"] = {k: v for k, v in guard.SEC_DEFAULTS.items() if k not in guard.SEC_SECRET}
    return out


_INT_KEYS = {"abuse_threshold": (5, 100000), "abuse_window": (30, 86400), "ban_level_ttl": (3600, 90 * 86400),
             "client_max_ips": (0, 100000), "client_ips_window": (60, 86400), "suspend_seconds": (60, 30 * 86400),
             "captcha_after": (0, 100), "alert_5xx_threshold": (1, 100000)}


@router.put("/settings")
async def put_sec(data: dict, request: Request, a: Admin = Depends(is_super), db: AsyncSession = Depends(get_db)):
    changed = []
    for k, v in data.items():
        if k not in guard.SEC_DEFAULTS or v is None:
            continue
        v = str(v).strip()
        if k in guard.SEC_SECRET and not v:
            continue  # bo'sh = o'zgartirmaslik
        if k in _INT_KEYS:
            lo, hi = _INT_KEYS[k]
            if not v.isdigit() or not lo <= int(v) <= hi:
                raise HTTPException(400, f"{k}: {lo}–{hi} oralig'ida butun son")
        if k in ("auto_ban_enabled", "alerts_enabled") and v not in ("0", "1"):
            raise HTTPException(400, f"{k}: 0 yoki 1")
        if k == "ban_steps" and not all(x.strip().isdigit() and int(x) >= 60 for x in v.split(",")):
            raise HTTPException(400, "ban_steps: soniyalar vergul bilan, masalan 900,3600,86400")
        if k == "alert_events":
            v = ",".join(x for x in v.split(",") if x in guard.EVENT_LABELS)
        row = await db.get(Setting, "sec_" + k)
        if row is None:
            row = Setting(key="sec_" + k)
            db.add(row)
        secret = k in guard.SEC_SECRET
        row.value, row.is_secret = (encrypt(v) if secret else v), secret
        changed.append(k)
    await audit(db, a.username, "security_settings", "", {"keys": changed}, client_ip(request))
    await db.commit()
    await bump_version()
    return {"ok": True, "changed": changed}


class TgIn(BaseModel):
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


@router.post("/telegram-test")
async def tg_test(data: TgIn, a: Admin = Depends(is_super)):
    await state.ensure_fresh()
    ok, errmsg = await guard.send_telegram(
        f"✅ <b>HEMIS Gateway</b>\nTest xabar. Ogohlantirishlar shu chatga keladi.\nYuborgan: {a.username}",
        token=data.telegram_bot_token or None, chat_id=data.telegram_chat_id or None)
    return {"ok": ok, "error": errmsg}


@router.get("/events")
async def events(a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db), type: str | None = None,
                 page: int = 1, limit: int = 50):
    limit = max(1, min(limit, 200))
    q = select(SecurityEvent)
    if type:
        q = q.where(SecurityEvent.type == type)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await db.execute(q.order_by(SecurityEvent.id.desc()).offset((page - 1) * limit).limit(limit))).scalars()
    return {"total": total, "labels": guard.EVENT_LABELS, "items": [
        {"id": r.id, "ts": iso(r.ts), "type": r.type, "severity": r.severity, "ip": r.ip, "client_id": r.client_id,
         "message": r.message} for r in rows]}


@router.get("/overview")
async def overview(request: Request, a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    rules = (await db.execute(select(IpRule))).scalars().all()
    active = [r for r in rules if _active(r)]
    ev24 = dict((await db.execute(select(SecurityEvent.type, func.count()).where(
        SecurityEvent.ts >= now - timedelta(hours=24)).group_by(SecurityEvent.type))).all())
    suspended = (await db.execute(select(func.count(Client.id)).where(Client.suspended_until > now))).scalar()
    top = [{"ip": r[0], "count": r[1]} for r in (await db.execute(
        select(RequestLog.ip, func.count()).where(RequestLog.ts >= now - timedelta(hours=1),
                                                  RequestLog.status.in_([400, 401, 403, 404]))
        .group_by(RequestLog.ip).order_by(func.count().desc()).limit(10))).all()]
    blocked = {r.cidr for r in active if r.action == "block"}
    for t in top:
        t["blocked"] = t["ip"] in blocked
    return {"active_blocks": sum(1 for r in active if r.action == "block"),
            "auto_blocks": sum(1 for r in active if r.action == "block" and r.auto),
            "allow_rules": sum(1 for r in active if r.action == "allow"), "suspended_clients": suspended,
            "events_24h": ev24, "top_denied_ips_1h": top, "my_ip": client_ip(request)}


class SuspendIn(BaseModel):
    minutes: int = Field(60, ge=1, le=30 * 24 * 60)
    reason: str = "qo'lda to'xtatildi"


@router.post("/clients/{cid}/suspend")
async def suspend(cid: int, data: SuspendIn, request: Request, a: Admin = Depends(can_edit),
                  db: AsyncSession = Depends(get_db)):
    await guard.suspend_client(cid, data.minutes * 60, f"{data.reason} (admin: {a.username})", by=a.username)
    await audit(db, a.username, "client_suspend", f"client:{cid}", data.model_dump(), client_ip(request))
    await db.commit()
    return {"ok": True}


@router.post("/clients/{cid}/resume")
async def resume(cid: int, request: Request, a: Admin = Depends(can_edit), db: AsyncSession = Depends(get_db)):
    await guard.resume_client(cid, a.username)
    await audit(db, a.username, "client_resume", f"client:{cid}", {}, client_ip(request))
    await db.commit()
    return {"ok": True}
