# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Xavfsizlik qo'riqchisi: IP qora/oq ro'yxati, bosqichma-bosqich avtomatik ban,
kalit o'g'irlanishini aniqlash, xavfsizlik hodisalari, Telegram ogohlantirishlar, fail2ban uchun log."""
import asyncio
import html
import ipaddress
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from sqlalchemy import delete, select, update

from .config import settings
from .db import SessionLocal
from .kv import kv
from .models import Client, IpRule, SecurityEvent
from .state import bump_version, state

log = logging.getLogger("gateway.guard")

# Panelda o'zgartiriladigan sozlamalar va standart qiymatlari
SEC_DEFAULTS = {
    "auto_ban_enabled": "1",
    "abuse_threshold": "50",       # oyna ichida shuncha rad etilgan so'rov (401/403/404/400) -> ban
    "abuse_window": "300",         # soniya
    "ban_steps": "900,3600,86400",  # 1-ban 15 daq, 2-si 1 soat, keyingilari 24 soat
    "ban_level_ttl": "604800",     # bosqich hisobi 7 kun saqlanadi
    "client_max_ips": "20",        # bitta kalit oyna ichida shuncha turli IP dan ishlatilsa -> to'xtatish (0 = o'chiq)
    "client_ips_window": "600",
    "suspend_seconds": "3600",
    "captcha_after": "3",          # shuncha xato logindan keyin captcha
    "alert_5xx_threshold": "50",   # 5 daqiqada shuncha 5xx -> ogohlantirish
    "alerts_enabled": "1",
    "alert_events": "ip_banned,client_suspended,admin_lock,admin_new_ip,upstream_auth,errors_5xx,login_bruteforce,spec_changed,spec_auto_applied,spec_sync_error",
    "telegram_chat_id": "",
    "telegram_bot_token": "",      # maxfiy (shifrlanadi)
}
SEC_SECRET = {"telegram_bot_token"}
EVENT_LABELS = {
    "ip_banned": "IP bloklandi", "ip_unbanned": "IP blokdan chiqarildi", "client_suspended": "Mijoz to'xtatildi",
    "client_resumed": "Mijoz qayta yoqildi", "admin_lock": "Admin akkaunt bloklandi", "admin_new_ip": "Admin yangi IP dan kirdi",
    "upstream_auth": "HEMIS token xatosi", "errors_5xx": "Server xatolari ko'paydi", "login_bruteforce": "Login urinishlari ko'p",
    "ip_list_import": "IP ro'yxat importi", "spec_changed": "HEMIS API hujjati o'zgardi",
    "spec_applied": "HEMIS API hujjati yangilandi",
    "spec_auto_applied": "HEMIS bilan avtomatik sinxronlandi", "spec_sync_error": "HEMIS docs sinxronlash xatosi", "test": "Test xabar",
}
AREAS = ("all", "gateway", "admin", "docs")


def _org() -> str:
    from .branding import org_short, public_base
    return " · ".join(x for x in (org_short() or "HEMIS Gateway", public_base().replace("https://", "")) if x)


def sec(key: str) -> str:
    v = state.settings.get("sec_" + key)
    return v if v not in (None, "") else SEC_DEFAULTS.get(key, "")


def sec_int(key: str) -> int:
    try:
        return int(sec(key))
    except ValueError:
        return int(SEC_DEFAULTS[key])


def _now():
    return datetime.now(timezone.utc)


def _aware(d):
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


# ---------------- fail2ban log ----------------

def _seclog(line: str):
    try:
        p = Path(settings.SECURITY_LOG)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(f"{_now().strftime('%Y-%m-%dT%H:%M:%SZ')} {line}\n")
    except OSError:
        log.warning("security.log ga yozib bo'lmadi")


# ---------------- Telegram ----------------

_tg: httpx.AsyncClient | None = None


async def send_telegram(text: str, token: str | None = None, chat_id: str | None = None) -> tuple[bool, str]:
    global _tg
    token = token or sec("telegram_bot_token")
    chat_id = chat_id or sec("telegram_chat_id")
    if not token or not chat_id:
        return False, "Telegram sozlanmagan"
    if _tg is None:
        _tg = httpx.AsyncClient(timeout=10)
    try:
        r = await _tg.post(f"https://api.telegram.org/bot{token}/sendMessage",
                           json={"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                                 "disable_web_page_preview": True})
        ok = r.status_code == 200
        return ok, "" if ok else r.text[:200]
    except httpx.HTTPError as ex:
        return False, str(ex)[:200]


async def _alert(etype: str, message: str, ip: str, dedupe: str | None):
    if sec("alerts_enabled") != "1" or etype not in sec("alert_events").split(","):
        return
    if dedupe and not await kv.setnx(f"alert:{etype}:{dedupe}", "1", 600):
        return  # 10 daqiqada bir xil hodisa qayta yuborilmaydi
    sev = "🔴" if etype in ("ip_banned", "client_suspended", "admin_lock", "upstream_auth") else "🟠"
    text = (f"{sev} <b>{html.escape(EVENT_LABELS.get(etype, etype))}</b>\n{html.escape(message)}"
            + (f"\nIP: <code>{html.escape(ip)}</code>" if ip else "")
            + f"\n<i>{_org()} · {_now().strftime('%d.%m.%Y %H:%M')} UTC</i>")
    ok, err = await send_telegram(text)
    if not ok and err != "Telegram sozlanmagan":
        log.warning("Telegram xabar yuborilmadi: %s", err)


async def event(etype: str, message: str, severity: str = "info", ip: str = "", client_id: int | None = None,
                details: dict | None = None, alert: bool = True, dedupe: str | None = None):
    try:
        async with SessionLocal() as db:
            db.add(SecurityEvent(type=etype, severity=severity, ip=ip, client_id=client_id, message=message[:2000],
                                 details=details or {}))
            await db.commit()
    except Exception:  # noqa: BLE001
        log.exception("hodisani yozib bo'lmadi")
    if alert:
        asyncio.create_task(_alert(etype, message, ip, dedupe))


def fire(coro):
    """So'rovni kechiktirmaslik uchun fon vazifasi."""
    t = asyncio.create_task(coro)
    t.add_done_callback(lambda x: x.exception() and log.error("guard: %s", x.exception()))


# ---------------- IP holati ----------------

async def ip_status(ip: str, area: str) -> tuple[str | None, object]:
    """('allow'|'block'|None, rule)"""
    await state.ensure_fresh()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    now = _now()
    blocked = None
    for net, r in state.ip_rules:
        if r.area not in ("all", area) or (r.expires_at and _aware(r.expires_at) < now):
            continue
        if addr.version == net.version and addr in net:
            if r.action == "allow":
                return "allow", r
            blocked = blocked or r
    if blocked:
        return "block", blocked
    if await kv.get(f"ban:{ip}"):
        return "block", None
    return None, None


async def is_trusted(ip: str) -> bool:
    st, _ = await ip_status(ip, "all")
    return st == "allow"


# ---------------- ban / unban ----------------

async def ban_ip(cidr: str, seconds: int | None, reason: str, auto: bool, by: str = "system",
                 area: str = "all") -> IpRule:
    net = ipaddress.ip_network(cidr, strict=False)
    cidr = str(net.network_address) if net.num_addresses == 1 else str(net)
    exp = _now() + timedelta(seconds=seconds) if seconds else None
    async with SessionLocal() as db:
        await db.execute(delete(IpRule).where(IpRule.cidr == cidr, IpRule.action == "block", IpRule.area == area))
        r = IpRule(cidr=cidr, action="block", area=area, reason=reason[:256], auto=auto, expires_at=exp, created_by=by)
        db.add(r)
        await db.commit()
    if net.num_addresses == 1 and area == "all":
        await kv.set(f"ban:{cidr}", reason[:100] or "ban", ex=seconds or 10 * 365 * 86400)
    await bump_version()
    _seclog(f"BAN ip={cidr} duration={seconds or 0} auto={int(auto)} reason={reason.replace(' ', '_')[:80]}")
    dur = f"{seconds // 60} daqiqa" if seconds and seconds < 7200 else (f"{seconds // 3600} soat" if seconds else "doimiy")
    await event("ip_banned", f"{cidr} bloklandi ({dur}). Sabab: {reason}" + ("" if auto else f". Admin: {by}"),
                "high", ip=cidr, details={"seconds": seconds, "auto": auto, "by": by}, dedupe=cidr)
    return r


async def unban(rule_id: int, by: str) -> bool:
    async with SessionLocal() as db:
        r = await db.get(IpRule, rule_id)
        if not r:
            return False
        cidr = r.cidr
        await db.delete(r)
        await db.commit()
    await kv.delete(f"ban:{cidr}")
    await kv.delete(f"abuse:{cidr}")
    await bump_version()
    _seclog(f"UNBAN ip={cidr} by={by}")
    await event("ip_unbanned", f"{cidr} blokdan chiqarildi. Admin: {by}", ip=cidr, alert=False)
    return True


async def record_abuse(ip: str, weight: int = 1, why: str = ""):
    """Rad etilgan so'rovni hisoblaydi; chegaradan oshsa IP ni bosqichma-bosqich bloklaydi."""
    if not ip or sec("auto_ban_enabled") != "1":
        return
    n = 0
    for _ in range(max(1, weight)):
        n = await kv.incr(f"abuse:{ip}", sec_int("abuse_window"))
    if n < sec_int("abuse_threshold"):
        return
    if await is_trusted(ip) or not await kv.setnx(f"banning:{ip}", "1", 15):
        return
    if await kv.get(f"ban:{ip}"):
        return
    level = await kv.incr(f"banlvl:{ip}", sec_int("ban_level_ttl"))
    steps = [int(x) for x in sec("ban_steps").split(",") if x.strip().isdigit()] or [900, 3600, 86400]
    seconds = steps[min(level - 1, len(steps) - 1)]
    await kv.delete(f"abuse:{ip}")
    await ban_ip(ip, seconds, f"avtomatik: {n} ta rad etilgan so'rov ({why or 'skaner/brute-force'}), {level}-marta",
                 auto=True)


# ---------------- kalit o'g'irlanishi ----------------

async def check_client_ips(c, ip: str):
    limit = c.max_distinct_ips if c.max_distinct_ips is not None else sec_int("client_max_ips")
    if not limit or c.allowed_ips:   # IP lari cheklangan mijozda bu tekshiruv kerak emas
        return
    window = sec_int("client_ips_window")
    bucket = int(time.time() // window)
    if not await kv.setnx(f"cip:{c.id}:{bucket}:{ip}", "1", window * 2):
        return
    n = await kv.incr(f"cipn:{c.id}:{bucket}", window * 2)
    if n > limit and await kv.setnx(f"suspending:{c.id}", "1", 60):
        await suspend_client(c.id, sec_int("suspend_seconds"),
                             f"kalit {window // 60} daqiqada {n} ta turli IP dan ishlatildi (limit {limit}) — o'g'irlangan bo'lishi mumkin",
                             ip=ip)


async def suspend_client(cid: int, seconds: int, reason: str, ip: str = "", by: str = "system"):
    until = _now() + timedelta(seconds=seconds)
    async with SessionLocal() as db:
        c = await db.get(Client, cid)
        if not c:
            return
        c.suspended_until, c.suspend_reason = until, reason[:256]
        name = c.name
        await db.commit()
    await bump_version()
    await event("client_suspended", f"«{name}» {seconds // 60} daqiqaga to'xtatildi: {reason}", "high", ip=ip,
                client_id=cid, dedupe=str(cid))


async def resume_client(cid: int, by: str):
    async with SessionLocal() as db:
        await db.execute(update(Client).where(Client.id == cid).values(suspended_until=None, suspend_reason=""))
        await db.commit()
    await kv.delete_prefix(f"cipn:{cid}:")
    await bump_version()
    await event("client_resumed", f"Mijoz #{cid} qayta yoqildi. Admin: {by}", client_id=cid, alert=False)


# ---------------- 5xx va login ----------------

async def note_5xx():
    n = await kv.incr(f"5xx:{int(time.time() // 300)}", 400)
    if n == sec_int("alert_5xx_threshold"):
        await event("errors_5xx", f"Oxirgi 5 daqiqada {n} ta server xatosi (HEMIS yoki gateway). Panelda jurnalni tekshiring.",
                    "warn", dedupe="5xx")


async def login_failed(kind: str, ip: str, who: str = ""):
    n = await kv.incr(f"loginfail:{kind}:{ip}", 900)
    await record_abuse(ip, 3, f"{kind} login")
    if n in (10, 30):
        await event("login_bruteforce", f"{kind} sahifasiga {ip} dan 15 daqiqada {n} ta xato login urinishi"
                    + (f" (oxirgi login: {who})" if who else ""), "warn", ip=ip, dedupe=f"{kind}:{ip}")


async def login_ok(kind: str, ip: str):
    await kv.delete(f"loginfail:{kind}:{ip}")


async def captcha_needed(kind: str, ip: str) -> bool:
    n = int(await kv.get(f"loginfail:{kind}:{ip}") or 0)
    return n >= sec_int("captcha_after")


async def cleanup_expired():
    async with SessionLocal() as db:
        await db.execute(delete(IpRule).where(IpRule.expires_at.is_not(None), IpRule.expires_at < _now()))
        await db.commit()
