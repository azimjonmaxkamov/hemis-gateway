# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select

from . import guard, logwriter, upstream
from .admin_api import router as admin_router
from .admin_auth import ensure_initial_admin, router as auth_router
from .captcha import router as captcha_router
from .branding import router as branding_router
from .setup_api import router as setup_router
from .security import client_ip
from .catalog import sync_catalog
from .config import settings
from .db import SessionLocal, init_db
from .docs_portal import router as docs_router
from .models import Endpoint
from .proxy import router as proxy_router
from .state import state
from .stats_api import router as stats_router
from .security_api import router as security_router
from .iplists import router as iplists_router
from .spec_update import autocheck_loop, ensure_baseline, router as spec_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("gateway")
STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await init_db()
    except Exception:  # noqa: BLE001  (bir nechta worker bir vaqtda yaratganda)
        log.info("init_db: jadvallar allaqachon mavjud")
    async with SessionLocal() as db:
        try:
            pw = await ensure_initial_admin(db)
        except Exception:  # noqa: BLE001
            await db.rollback()
            pw = None
        if pw:
            log.warning("=" * 60)
            log.warning("Birinchi superadmin yaratildi: login=%s parol=%s", settings.INIT_ADMIN_USERNAME, pw)
            log.warning("Kirgandan so'ng parolni darhol o'zgartiring va 2FA yoqing!")
            log.warning("=" * 60)
        n = (await db.execute(select(func.count(Endpoint.id)))).scalar()
        if not n and Path(settings.OPENAPI_PATH).exists():
            try:
                res = await sync_catalog(db)
                log.info("Endpoint katalogi import qilindi: %s", res)
            except Exception:  # noqa: BLE001  (boshqa worker allaqachon import qilgan)
                await db.rollback()
                log.info("Endpoint katalogi boshqa worker tomonidan import qilingan")
    if settings.ENV == "production" and (settings.SECRET_KEY.startswith("change-me")
                                         or settings.API_KEY_PEPPER.startswith("change-me")
                                         or len(settings.SECRET_KEY) < 32):
        raise RuntimeError("SECRET_KEY / API_KEY_PEPPER o'rnatilmagan. `python -m app.cli gen-secrets` bilan yarating.")
    if settings.ENV == "production":
        # ENCRYPTION_KEY bo'sh/yaroqsiz bo'lsa HEMIS tokenini saqlashda keyinroq tushunarsiz xato bo'ladi —
        # shuning uchun hoziroq, startup'da aniq xato beramiz.
        try:
            from cryptography.fernet import Fernet
            Fernet((settings.ENCRYPTION_KEY or "").encode())
        except Exception:  # noqa: BLE001
            raise RuntimeError("ENCRYPTION_KEY yaroqsiz yoki o'rnatilmagan. "
                               "`python -m app.cli gen-secrets` bilan yarating.")
    import os
    from .kv import MemoryKV, kv as _kv
    if isinstance(_kv, MemoryKV) and int(os.environ.get("WORKERS", "1") or 1) > 1:
        log.warning("REDIS_URL berilmagan va bir nechta worker ishlayapti: limitlar va kesh har bir workerda alohida "
                    "hisoblanadi. Production uchun Redis ishlating (docker-compose da bor).")
    await state.reload()
    logwriter.start()
    try:
        await ensure_baseline()
    except OSError:
        log.warning("docs arxivini yaratib bo'lmadi")
    import asyncio
    spec_task = asyncio.create_task(autocheck_loop())
    yield
    spec_task.cancel()
    await logwriter.drain()
    await upstream.close()


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    p = request.url.path
    if p.startswith("/admin") or p.startswith("/portal") or p.startswith("/docs") or p == "/":
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
    if p.startswith("/api/admin"):
        resp.headers["Cache-Control"] = "no-store"
    if settings.ENV == "production":
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


@app.middleware("http")
async def ip_guard(request: Request, call_next):
    """Qora ro'yxatdagi / avtomatik ban qilingan IP larni eng birinchi bosqichda to'xtatadi."""
    p = request.url.path
    if p == "/healthz" or p.startswith("/static/"):
        return await call_next(request)
    if p.startswith(("/rest/", "/fast/", "/gateway/")):
        area = "gateway"
    elif p.startswith(("/admin", "/api/admin")):
        area = "admin"
    elif p.startswith("/docs"):
        area = "docs"
    else:
        area = "all"
    st, _rule = await guard.ip_status(client_ip(request), area)
    if st == "block":
        return JSONResponse({"success": False, "error": "IP manzilingiz bloklangan", "code": 403,
                             "gateway_code": "ip_blocked"}, status_code=403)
    return await call_next(request)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("Kutilmagan xato: %s", request.url.path)
    return JSONResponse({"success": False, "error": "Ichki xato", "code": 500}, status_code=500)


app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(stats_router)
app.include_router(spec_router)
app.include_router(iplists_router)
app.include_router(security_router)
app.include_router(branding_router)
app.include_router(setup_router)
app.include_router(captcha_router)
app.include_router(docs_router)
app.include_router(proxy_router)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/healthz", include_in_schema=False)
async def health():
    return {"ok": True}


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse("/portal")


@app.get("/admin", include_in_schema=False)
@app.get("/admin/{rest:path}", include_in_schema=False)
async def admin_spa(rest: str = ""):
    return FileResponse(STATIC / "admin.html")


@app.get("/portal", include_in_schema=False)
async def portal():
    return FileResponse(STATIC / "portal.html")
