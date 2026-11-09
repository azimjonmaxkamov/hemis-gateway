# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Buyruq qatori vositalari.

  python -m app.cli init                     — jadvallar, katalog, birinchi superadmin
  python -m app.cli reset-password <login>   — admin parolini tiklash (yangi parol chiqariladi)
  python -m app.cli sync-catalog             — HEMIS dan API hujjatini yuklab, katalogni yangilash
  python -m app.cli gen-secrets              — .env uchun tasodifiy kalitlar
"""
import asyncio
import secrets
import sys

from cryptography.fernet import Fernet
from sqlalchemy import func, select


async def init():
    from .admin_auth import ensure_initial_admin
    from .catalog import sync_catalog
    from .db import SessionLocal, init_db
    from .models import Endpoint
    await init_db()
    async with SessionLocal() as db:
        pw = await ensure_initial_admin(db)
        if pw:
            print(f"\n*** Superadmin yaratildi: login=admin  parol={pw}\n*** Kirgach darhol o'zgartiring va 2FA yoqing!\n")
        from pathlib import Path
        from .config import settings
        if not (await db.execute(select(func.count(Endpoint.id)))).scalar():
            if Path(settings.OPENAPI_PATH).exists():
                print("Katalog:", await sync_catalog(db))
            else:
                print("Endpoint katalogi bo'sh — panelda Sozlamalar → «Saqlash va sinxronlash» orqali HEMIS dan yuklanadi.")


async def reset_password(username: str):
    from .db import SessionLocal
    from .models import Admin
    from .security import hash_password
    async with SessionLocal() as db:
        a = (await db.execute(select(Admin).where(Admin.username == username))).scalar_one_or_none()
        if not a:
            print("Topilmadi"); return
        pw = secrets.token_urlsafe(12) + "7a"
        a.password_hash, a.totp_secret, a.failed_logins, a.locked_until = hash_password(pw), None, 0, None
        a.token_version += 1
        await db.commit()
        print(f"Yangi parol: {pw}  (2FA o'chirildi)")


async def sync():
    from pathlib import Path
    import json
    from .config import settings
    from .db import SessionLocal
    from .kv import kv
    from .setup_api import full_sync
    from .state import state
    await state.reload()
    res = await full_sync({}, "cli")
    for s in res["steps"]:
        print(("OK   " if s["ok"] else "XATO ") + s["message"])
    await kv.set("cfg_ver", secrets.token_hex(4))


def gen():
    print(f"SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"API_KEY_PEPPER={secrets.token_urlsafe(32)}")
    print(f"ENCRYPTION_KEY={Fernet.generate_key().decode()}")
    print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "init":
        asyncio.run(init())
    elif cmd == "reset-password" and len(sys.argv) > 2:
        asyncio.run(reset_password(sys.argv[2]))
    elif cmd == "sync-catalog":
        asyncio.run(sync())
    elif cmd == "gen-secrets":
        gen()
    else:
        print(__doc__)
