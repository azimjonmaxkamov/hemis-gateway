# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""So'rov loglarini fon rejimida paket-paket bazaga yozish (proxy tezligiga ta'sir qilmaydi)."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, update

from .config import settings
from .db import SessionLocal
from .models import Client, RequestLog

log = logging.getLogger("gateway.logs")
_queue: asyncio.Queue = asyncio.Queue(maxsize=50000)
_task: asyncio.Task | None = None


def push(**row):
    try:
        _queue.put_nowait(row)
    except asyncio.QueueFull:
        log.warning("log navbati to'ldi, yozuv tashlab yuborildi")


async def _flush(batch: list[dict]):
    if not batch:
        return
    used: dict[int, datetime] = {}
    for r in batch:
        if r.get("client_id") and r.get("status", 0) < 400:
            used[r["client_id"]] = r["ts"]
    async with SessionLocal() as db:
        db.add_all([RequestLog(**r) for r in batch])
        for cid, ts in used.items():
            await db.execute(update(Client).where(Client.id == cid).values(last_used_at=ts))
        await db.commit()


async def _worker():
    last_cleanup = datetime.now(timezone.utc) - timedelta(days=1)
    while True:
        batch = [await _queue.get()]
        try:
            while len(batch) < 500:
                batch.append(_queue.get_nowait())
        except asyncio.QueueEmpty:
            pass
        try:
            await _flush(batch)
        except Exception:  # noqa: BLE001
            log.exception("loglarni yozishda xato")
        now = datetime.now(timezone.utc)
        if now - last_cleanup > timedelta(hours=6):
            last_cleanup = now
            try:
                async with SessionLocal() as db:
                    await db.execute(delete(RequestLog).where(
                        RequestLog.ts < now - timedelta(days=settings.LOG_RETENTION_DAYS)))
                    await db.commit()
                from .guard import cleanup_expired
                await cleanup_expired()
            except Exception:  # noqa: BLE001
                log.exception("eski loglarni tozalashda xato")
        await asyncio.sleep(0.5)


def start():
    global _task
    if _task is None:
        _task = asyncio.create_task(_worker())


async def drain():
    """Testlar va to'xtash uchun: navbatdagi hamma yozuvlarni yozib yuboradi."""
    batch = []
    while not _queue.empty():
        batch.append(_queue.get_nowait())
    await _flush(batch)
