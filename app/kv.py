# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Redis (yoki xotira ichidagi zaxira) — rate limit, kesh, konfiguratsiya versiyasi."""
import asyncio
import time

from .config import settings

try:
    import redis.asyncio as aioredis
except ImportError:  # pragma: no cover
    aioredis = None


class MemoryKV:
    def __init__(self):
        self.d: dict[str, tuple[object, float]] = {}
        self.lock = asyncio.Lock()

    def _get(self, k):
        v = self.d.get(k)
        if v is None:
            return None
        if v[1] and v[1] < time.time():
            self.d.pop(k, None)
            return None
        return v[0]

    async def get(self, k):
        return self._get(k)

    async def set(self, k, v, ex: int | None = None):
        self.d[k] = (v, time.time() + ex if ex else 0)
        if len(self.d) > 50000:
            now = time.time()
            for kk in [kk for kk, vv in self.d.items() if vv[1] and vv[1] < now]:
                self.d.pop(kk, None)

    async def incr(self, k, ex: int) -> int:
        async with self.lock:
            if self._get(k) is not None:
                cur, exp = self.d[k]
                cur = int(cur) + 1
            else:
                cur, exp = 1, time.time() + ex
            self.d[k] = (cur, exp)
            return cur

    async def setnx(self, k, v, ex: int) -> bool:
        async with self.lock:
            if self._get(k) is not None:
                return False
            self.d[k] = (v, time.time() + ex)
            return True

    async def delete(self, k):
        self.d.pop(k, None)

    async def ttl(self, k) -> int:
        v = self.d.get(k)
        return int(v[1] - time.time()) if v and v[1] else -1

    async def delete_prefix(self, prefix: str) -> int:
        ks = [k for k in self.d if k.startswith(prefix)]
        for k in ks:
            self.d.pop(k, None)
        return len(ks)

    async def ping(self):
        return True


class RedisKV:
    def __init__(self, url: str):
        self.r = aioredis.from_url(url, decode_responses=False)

    async def get(self, k):
        v = await self.r.get(k)
        if v is None:
            return None
        try:
            return v.decode()
        except UnicodeDecodeError:
            return v

    async def get_bytes(self, k):
        return await self.r.get(k)

    async def set(self, k, v, ex: int | None = None):
        await self.r.set(k, v, ex=ex)

    async def incr(self, k, ex: int) -> int:
        p = self.r.pipeline()
        p.incr(k)
        p.expire(k, ex, nx=True)
        res = await p.execute()
        return int(res[0])

    async def setnx(self, k, v, ex: int) -> bool:
        return bool(await self.r.set(k, v, ex=ex, nx=True))

    async def delete(self, k):
        await self.r.delete(k)

    async def ttl(self, k) -> int:
        return int(await self.r.ttl(k))

    async def delete_prefix(self, prefix: str) -> int:
        n = 0
        async for k in self.r.scan_iter(match=prefix + "*", count=500):
            await self.r.delete(k)
            n += 1
        return n

    async def ping(self):
        return await self.r.ping()


kv = RedisKV(settings.REDIS_URL) if (settings.REDIS_URL and aioredis) else MemoryKV()


async def kv_get_bytes(k):
    if isinstance(kv, RedisKV):
        return await kv.get_bytes(k)
    v = await kv.get(k)
    return v


async def upstream_slot(max_rps: int, max_wait: float = 10.0) -> bool:
    """HEMIS Backend API ga sekundiga max_rps dan ortiq so'rov yubormaslik (barcha workerlar uchun umumiy)."""
    deadline = time.time() + max_wait
    while True:
        sec = int(time.time())
        n = await kv.incr(f"up:{sec}", 3)
        if n <= max_rps:
            return True
        if time.time() > deadline:
            return False
        await asyncio.sleep(max(0.02, (sec + 1) - time.time()))
