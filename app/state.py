# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Xotiradagi konfiguratsiya keshi: endpointlar, mijozlar, ruxsatlar, sozlamalar.
Admin o'zgartirish kiritganda versiya oshiriladi va barcha workerlar 1 soniya ichida yangilanadi."""
import asyncio
import time
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .catalog import Router
from .config import settings
from .db import SessionLocal
from .kv import MemoryKV, kv
from .models import Client, Endpoint, IpRule, Setting
from .security import decrypt


def _snap(obj, cols):
    return SimpleNamespace(**{c: getattr(obj, c) for c in cols})


_EP_COLS = ["id", "method", "path", "upstream", "group", "summary", "auth_mode", "params", "has_body",
            "is_enabled", "risk", "cache_ttl", "in_spec"]
_CL_COLS = ["id", "name", "key_prefix", "key_hash", "is_active", "expires_at", "allowed_ips", "allowed_origins",
            "rate_per_second", "rate_per_minute", "daily_quota", "scope", "strict_scope", "allow_personal_data",
            "suspended_until", "suspend_reason", "max_distinct_ips"]
_PM_COLS = ["id", "endpoint_id", "allowed_params", "locked_params", "max_limit", "hidden_fields", "allow_personal"]


class State:
    def __init__(self):
        self.endpoints: dict[int, SimpleNamespace] = {}
        self.router = Router()
        self.clients: dict[str, SimpleNamespace] = {}   # key_prefix -> client
        self.settings: dict[str, str] = {}
        self.ip_rules: list = []
        self.secret_errors: set = set()   # [(ip_network, SimpleNamespace)]
        self.version = None
        self._checked = 0.0
        self._lock = asyncio.Lock()

    async def reload(self):
        async with SessionLocal() as db:
            eps = (await db.execute(select(Endpoint))).scalars().all()
            cls = (await db.execute(select(Client).options(selectinload(Client.permissions)))).scalars().all()
            sts = (await db.execute(select(Setting))).scalars().all()
            rules = (await db.execute(select(IpRule))).scalars().all()
        self.endpoints = {e.id: _snap(e, _EP_COLS) for e in eps}
        self.router.build(list(self.endpoints.values()))
        clients = {}
        for c in cls:
            s = _snap(c, _CL_COLS)
            s.perms = {p.endpoint_id: _snap(p, _PM_COLS) for p in c.permissions}
            clients[c.key_prefix] = s
        self.clients = clients
        self.settings = {s.key: (decrypt(s.value) if s.is_secret else s.value) for s in sts}
        # ENCRYPTION_KEY/SECRET_KEY o'zgargan bo'lsa saqlangan tokenlar ochilmaydi — buni panelda ko'rsatamiz
        self.secret_errors = {s.key for s in sts if s.is_secret and s.value and not self.settings.get(s.key)}
        import ipaddress
        ipr = []
        for r in rules:
            try:
                ipr.append((ipaddress.ip_network(r.cidr, strict=False),
                            _snap(r, ["id", "cidr", "action", "area", "reason", "auto", "expires_at"])))
            except ValueError:
                continue
        self.ip_rules = ipr

    async def ensure_fresh(self):
        now = time.time()
        if now - self._checked < 1.0 and self.version is not None:
            return
        self._checked = now
        if isinstance(kv, MemoryKV):
            # Redis yo'q: har bir worker o'z xotirasida — versiyani bazadan o'qiymiz (workerlar orasida sinxron)
            async with SessionLocal() as db:
                row = await db.get(Setting, "cfg_ver")
            ver = row.value if row else "0"
        else:
            ver = await kv.get("cfg_ver")
            ver = ver if ver is not None else "0"
        if ver != self.version:
            async with self._lock:
                if ver != self.version:
                    await self.reload()
                    self.version = ver

    def setting(self, key: str, default: str = "") -> str:
        return self.settings.get(key) or default

    @property
    def hemis_base(self) -> str:
        from .branding import normalize_hemis_base
        return normalize_hemis_base(self.setting("hemis_base_url", settings.HEMIS_BASE_URL))

    @property
    def hemis_token(self) -> str:
        return self.setting("hemis_admin_token", settings.HEMIS_ADMIN_TOKEN)

    @property
    def fast_base(self) -> str:
        return self.setting("fast_api_url", settings.HEMIS_FAST_API_URL).rstrip("/")

    @property
    def fast_token(self) -> str:
        return self.setting("fast_api_token", settings.HEMIS_FAST_API_TOKEN)


state = State()


async def bump_version():
    ver = str(time.time_ns())
    await kv.set("cfg_ver", ver)
    if isinstance(kv, MemoryKV):
        async with SessionLocal() as db:
            row = await db.get(Setting, "cfg_ver") or Setting(key="cfg_ver")
            row.value = ver
            db.add(row)
            await db.commit()
    state._checked = 0
