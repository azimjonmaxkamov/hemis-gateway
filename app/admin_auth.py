# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Admin panel autentifikatsiyasi: parol + ixtiyoriy 2FA (TOTP), httpOnly cookie, CSRF, IP cheklovi."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import get_db
from . import guard
from .captcha import verify_captcha
from .kv import kv
from .models import Admin, AdminAudit
from .security import (client_ip, create_admin_token, decode_admin_token, decrypt, encrypt, hash_password,
                       ip_allowed, new_totp_secret, password_problems, totp_uri, verify_password, verify_totp)

COOKIE = "hg_admin"
ROLES = ("superadmin", "admin", "auditor")
router = APIRouter(prefix="/api/admin/auth", tags=["Admin auth"])


async def audit(db: AsyncSession, admin: str, action: str, target: str = "", details: dict | None = None, ip: str = ""):
    db.add(AdminAudit(admin=admin, action=action, target=target[:256], details=details or {}, ip=ip))


def check_admin_ip(request: Request):
    if not ip_allowed(client_ip(request), settings.ADMIN_ALLOWED_IPS):
        raise HTTPException(403, "Admin panelga bu manzildan kirish taqiqlangan")


async def current_admin(request: Request, db: AsyncSession = Depends(get_db)) -> Admin:
    check_admin_ip(request)
    tok = request.cookies.get(COOKIE)
    p = decode_admin_token(tok) if tok else None
    if not p:
        raise HTTPException(401, "Tizimga kiring")
    if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "hg-admin":
        raise HTTPException(403, "CSRF tekshiruvi")
    a = await db.get(Admin, int(p["sub"]))
    if not a or not a.is_active or a.token_version != p.get("tv"):
        raise HTTPException(401, "Sessiya yaroqsiz")
    return a


def require(*roles: str):
    async def dep(a: Admin = Depends(current_admin)) -> Admin:
        if a.role not in roles:
            raise HTTPException(403, "Bu amal uchun huquqingiz yetarli emas")
        return a
    return dep


can_view = require("superadmin", "admin", "auditor")
can_edit = require("superadmin", "admin")
is_super = require("superadmin")


def admin_out(a: Admin) -> dict:
    return {"id": a.id, "username": a.username, "full_name": a.full_name, "role": a.role,
            "is_active": a.is_active, "totp_enabled": bool(a.totp_secret),
            "last_login_at": (a.last_login_at if a.last_login_at.tzinfo else a.last_login_at.replace(tzinfo=timezone.utc)).isoformat() if a.last_login_at else None}


class LoginIn(BaseModel):
    username: str
    password: str
    otp: str | None = None
    captcha_id: str | None = None
    captcha: str | None = None


def _lock(a: Admin, now, ip: str):
    a.failed_logins += 1
    if a.failed_logins >= settings.ADMIN_LOGIN_MAX_FAILS:
        a.locked_until = now + timedelta(minutes=settings.ADMIN_LOGIN_LOCK_MINUTES)
        a.failed_logins = 0
        guard.fire(guard.event("admin_lock", f"Admin «{a.username}» {settings.ADMIN_LOGIN_LOCK_MINUTES} daqiqaga bloklandi "
                               f"({settings.ADMIN_LOGIN_MAX_FAILS} ta xato urinish)", "high", ip=ip, dedupe=a.username))


@router.post("/login")
async def login(data: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    check_admin_ip(request)
    ip = client_ip(request)
    if await kv.incr(f"adminlogin:{ip}", 600) > 30:
        raise HTTPException(429, "Juda ko'p urinish. Keyinroq qayta urining")
    if await guard.captcha_needed("admin", ip) and not await verify_captcha(data.captcha_id, data.captcha):
        raise HTTPException(428, "Captcha noto'g'ri yoki kiritilmagan" if data.captcha else "Captcha kiriting")
    a = (await db.execute(select(Admin).where(Admin.username == data.username.strip()))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if a and a.locked_until and a.locked_until.replace(tzinfo=timezone.utc) > now:
        raise HTTPException(423, "Akkaunt vaqtincha bloklangan. Keyinroq urining")
    if not a or not a.is_active or not verify_password(data.password, a.password_hash):
        if a:
            _lock(a, now, ip)
            await audit(db, a.username, "login_failed", ip=ip)
            await db.commit()
        await guard.login_failed("admin", ip, data.username.strip()[:64])
        raise HTTPException(401, "Login yoki parol noto'g'ri")
    await guard.login_ok("admin", ip)   # parol to'g'ri — captcha hisobini tozalash
    if a.totp_secret:
        if not data.otp:
            return {"otp_required": True}
        if await kv.incr(f"adminotp:{a.id}", 900) > 10 or not verify_totp(decrypt(a.totp_secret), data.otp):
            _lock(a, now, ip)
            await audit(db, a.username, "otp_failed", ip=ip)
            await db.commit()
            raise HTTPException(401, "2FA kod noto'g'ri")
    first_login = a.last_login_at is None
    a.failed_logins = 0
    a.last_login_at = now
    await audit(db, a.username, "login", ip=ip)
    if await kv.setnx(f"adminip:{a.id}:{ip}", "1", 90 * 86400) and not first_login:
        guard.fire(guard.event("admin_new_ip", f"«{a.username}» ({a.role}) panelga yangi IP manzildan kirdi", "warn",
                               ip=ip, dedupe=f"{a.id}:{ip}"))
    await db.commit()
    response.set_cookie(COOKIE, create_admin_token(a.id, a.role, a.token_version), httponly=True,
                        secure=settings.ENV == "production", samesite="strict",
                        max_age=settings.ADMIN_SESSION_HOURS * 3600, path="/")
    return {"ok": True, "admin": admin_out(a)}


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    tok = request.cookies.get(COOKIE)
    p = decode_admin_token(tok) if tok else None
    if p:
        a = await db.get(Admin, int(p["sub"]))
        if a and a.token_version == p.get("tv"):
            a.token_version += 1  # cookie o'g'irlangan bo'lsa ham endi yaroqsiz
            await audit(db, a.username, "logout", ip=client_ip(request))
            await db.commit()
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(a: Admin = Depends(current_admin)):
    return admin_out(a)


class PasswordIn(BaseModel):
    old_password: str
    new_password: str


@router.post("/password")
async def change_password(data: PasswordIn, request: Request, response: Response,
                          a: Admin = Depends(current_admin), db: AsyncSession = Depends(get_db)):
    if not verify_password(data.old_password, a.password_hash):
        raise HTTPException(400, "Joriy parol noto'g'ri")
    if (p := password_problems(data.new_password)):
        raise HTTPException(400, p)
    a.password_hash = hash_password(data.new_password)
    a.token_version += 1
    await audit(db, a.username, "password_change", ip=client_ip(request))
    await db.commit()
    response.set_cookie(COOKIE, create_admin_token(a.id, a.role, a.token_version), httponly=True,
                        secure=settings.ENV == "production", samesite="strict",
                        max_age=settings.ADMIN_SESSION_HOURS * 3600, path="/")
    return {"ok": True}


@router.post("/2fa/setup")
async def tfa_setup(a: Admin = Depends(current_admin)):
    s = new_totp_secret()
    return {"secret": s, "uri": totp_uri(s, a.username)}


class TfaIn(BaseModel):
    secret: str | None = None
    code: str | None = None
    password: str | None = None


@router.post("/2fa/enable")
async def tfa_enable(data: TfaIn, request: Request, a: Admin = Depends(current_admin), db: AsyncSession = Depends(get_db)):
    if not verify_password(data.password or "", a.password_hash):
        raise HTTPException(400, "Parol noto'g'ri")
    if not data.secret or not verify_totp(data.secret, data.code or ""):
        raise HTTPException(400, "Kod noto'g'ri")
    a.totp_secret = encrypt(data.secret)
    await audit(db, a.username, "2fa_enable", ip=client_ip(request))
    await db.commit()
    return {"ok": True}


@router.post("/2fa/disable")
async def tfa_disable(data: TfaIn, request: Request, a: Admin = Depends(current_admin), db: AsyncSession = Depends(get_db)):
    if not verify_password(data.password or "", a.password_hash):
        raise HTTPException(400, "Parol noto'g'ri")
    a.totp_secret = None
    await audit(db, a.username, "2fa_disable", ip=client_ip(request))
    await db.commit()
    return {"ok": True}


async def ensure_initial_admin(db: AsyncSession):
    exists = (await db.execute(select(Admin.id).limit(1))).first()
    if exists:
        return None
    import secrets as _s
    pw = settings.INIT_ADMIN_PASSWORD or _s.token_urlsafe(12) + "9a"
    db.add(Admin(username=settings.INIT_ADMIN_USERNAME, full_name="Super admin", role="superadmin",
                 password_hash=hash_password(pw)))
    await db.commit()
    return pw
