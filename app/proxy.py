# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Gateway: tashqi tizimlar HEMIS ga faqat shu yerdan, ruxsat doirasida o'tadi.

  https://<gateway>/rest/v1/data/student-list?... -> <HEMIS>/rest/v1/data/student-list
  https://<gateway>/fast/student-gpa-summary      -> Fast API

Mijoz kaliti:  X-Gateway-Key: hg_xxx   yoki   Authorization: Bearer hg_xxx  (Backend/Public endpointlar uchun)
"""
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qsl

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from . import guard, logwriter
from .branding import public_base
from .config import settings
from .kv import kv, kv_get_bytes, upstream_slot
from .policy import evaluate, mask
from .security import client_ip, ip_allowed, parse_api_key, verify_api_key
from .state import state
from .upstream import http

router = APIRouter()

MAX_BODY = 25 * 1024 * 1024
PASS_RESP_HEADERS = {"content-type", "content-disposition", "content-language", "last-modified", "etag"}
PASS_REQ_HEADERS = {"accept-language", "content-type"}


def err(status: int, code: str, message: str, extra_headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"success": False, "error": message, "code": status, "gateway_code": code},
                        status_code=status, headers=extra_headers or {})


def _cors_headers(origin: str | None, client) -> dict:
    if origin and client and origin in (client.allowed_origins or []):
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                "Access-Control-Expose-Headers": "X-Request-Id, X-RateLimit-Remaining, X-Cache"}
    return {}


def _extract_key(request: Request) -> str | None:
    k = request.headers.get("x-gateway-key")
    if k:
        return k.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and auth[7:].strip().startswith("hg_"):
        return auth[7:].strip()
    return None


async def _authenticate(request: Request, ip: str):
    key = _extract_key(request)
    if not key:
        return None, err(401, "no_key", "Gateway kaliti yuborilmagan (X-Gateway-Key header)")
    prefix = parse_api_key(key)
    c = state.clients.get(prefix) if prefix else None
    if c is None or not verify_api_key(key, c.key_hash):
        # brute-force himoyasi: IP bo'yicha noto'g'ri kalitlar soni
        n = await kv.incr(f"badkey:{ip}", 600)
        if n > 30:
            return None, err(429, "too_many_bad_keys", "Juda ko'p noto'g'ri urinish. 10 daqiqadan keyin qayta urining")
        return None, err(401, "invalid_key", "Gateway kaliti noto'g'ri")
    if not c.is_active:
        return c, err(403, "client_disabled", "Mijoz faol emas")
    if c.suspended_until and c.suspended_until.replace(tzinfo=c.suspended_until.tzinfo or timezone.utc) > datetime.now(timezone.utc):
        return c, err(403, "client_suspended", "Kalit xavfsizlik sababli vaqtincha to'xtatilgan. Administratorga murojaat qiling")
    if c.expires_at and c.expires_at.replace(tzinfo=c.expires_at.tzinfo or timezone.utc) < datetime.now(timezone.utc):
        return c, err(403, "key_expired", "Kalit muddati tugagan")
    if not ip_allowed(ip, c.allowed_ips or []):
        return c, err(403, "ip_not_allowed", f"{ip} manzilidan kirishga ruxsat yo'q")
    origin = request.headers.get("origin")
    if origin and c.allowed_origins and origin not in c.allowed_origins:
        return c, err(403, "origin_not_allowed", "Ushbu domen (Origin) uchun ruxsat yo'q")
    return c, None


async def _rate_limit(c) -> tuple[JSONResponse | None, dict]:
    now = datetime.now(timezone.utc)
    headers = {}
    if c.rate_per_second:
        n = await kv.incr(f"rs:{c.id}:{int(now.timestamp())}", 3)
        if n > c.rate_per_second:
            return err(429, "rate_limited_second",
                       f"Soniyasiga {c.rate_per_second} tadan ortiq so'rov yuborib bo'lmaydi",
                       {"Retry-After": "1", "X-RateLimit-Second": str(c.rate_per_second)}), headers
    if c.rate_per_minute:
        n = await kv.incr(f"rl:{c.id}:{now:%Y%m%d%H%M}", 70)
        headers["X-RateLimit-Limit"] = str(c.rate_per_minute)
        headers["X-RateLimit-Remaining"] = str(max(0, c.rate_per_minute - n))
        if n > c.rate_per_minute:
            headers["Retry-After"] = str(60 - now.second)
            return err(429, "rate_limited", "Daqiqalik so'rovlar limiti tugadi", headers), headers
    if c.daily_quota:
        n = await kv.incr(f"dq:{c.id}:{now:%Y%m%d}", 90000)
        if n > c.daily_quota:
            return err(429, "quota_exceeded", "Kunlik so'rovlar kvotasi tugadi", headers), headers
    return None, headers


@router.options("/rest/{path:path}", include_in_schema=False)
@router.options("/fast/{path:path}", include_in_schema=False)
async def preflight(request: Request, path: str):
    await state.ensure_fresh()
    origin = request.headers.get("origin")
    allowed = any(origin in (c.allowed_origins or []) for c in state.clients.values() if c.is_active) if origin else False
    if not allowed:
        return Response(status_code=403)
    return Response(status_code=204, headers={
        "Access-Control-Allow-Origin": origin, "Vary": "Origin",
        "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE",
        "Access-Control-Allow-Headers": "Authorization, X-Gateway-Key, Content-Type, Accept-Language",
        "Access-Control-Max-Age": "600"})


@router.api_route("/rest/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
async def proxy_rest(request: Request, path: str):
    return await handle(request, "hemis", "/" + path)


@router.api_route("/fast/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
async def proxy_fast(request: Request, path: str):
    return await handle(request, "fast", "/" + path)


async def handle(request: Request, upstream: str, path: str):
    t0 = time.perf_counter()
    rid = uuid.uuid4().hex[:16]
    ip = client_ip(request)
    method = request.method
    raw_qs = request.url.query
    entry = dict(ts=datetime.now(timezone.utc), method=method, path=path[:255], query=raw_qs[:2000], ip=ip,
                 user_agent=request.headers.get("user-agent", "")[:256], status=0, client_id=None, client_name="",
                 endpoint_id=None)

    def finish(resp: Response, **kw):
        entry.update(kw)
        entry["status"] = resp.status_code
        entry["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if entry["status"] >= 400 and not entry.get("denied_reason"):
            try:
                entry["denied_reason"] = json.loads(resp.body).get("gateway_code", "")[:64]
            except Exception:  # noqa: BLE001
                pass
        logwriter.push(**entry)
        st = entry["status"]
        reason = entry.get("denied_reason") or ""
        # Faqat gateway o'zi rad etgan so'rovlar hisoblanadi (HEMIS ning o'z 404/401 javoblari emas)
        if reason and (st in (400, 401, 403, 404) or reason == "too_many_bad_keys") \
                and reason not in ("ip_blocked",) and not entry.get("upstream_status"):
            guard.fire(guard.record_abuse(ip, 1, entry.get("denied_reason", "")))
        elif st >= 500:
            guard.fire(guard.note_5xx())
            if entry.get("denied_reason") == "upstream_auth":
                guard.fire(guard.event("upstream_auth", "HEMIS admin tokeni rad etildi (401/403). Sozlamalardagi tokenni tekshiring.",
                                       "high", dedupe="token"))
        resp.headers["X-Request-Id"] = rid
        return resp

    await state.ensure_fresh()

    # --- yo'l xavfsizligi ---
    raw_path = request.scope.get("raw_path", b"").decode("latin-1")
    if "%" in raw_path or ".." in path or "//" in path or "\\" in path:
        return finish(err(400, "bad_path", "Noto'g'ri so'rov yo'li"))

    # --- autentifikatsiya ---
    c, e = await _authenticate(request, ip)
    if c is not None:
        entry.update(client_id=c.id, client_name=c.name)
    if e is not None:
        return finish(e)
    cors = _cors_headers(request.headers.get("origin"), c)

    guard.fire(guard.check_client_ips(c, ip))
    rl, rl_headers = await _rate_limit(c)
    if rl is not None:
        return finish(rl)

    # --- endpoint ---
    eid, path_params = state.router.match(upstream, method, path)
    ep = state.endpoints.get(eid) if eid else None
    if ep is None:
        return finish(err(404, "unknown_endpoint", "Bunday endpoint katalogda mavjud emas"))
    entry["endpoint_id"] = ep.id
    if not ep.in_spec:
        return finish(err(410, "endpoint_removed", "Bu endpoint HEMIS API hujjatidan olib tashlangan"))
    if not ep.is_enabled:
        return finish(err(403, "endpoint_disabled", "Endpoint vaqtincha o'chirilgan"))

    # --- ruxsat va filtrlar ---
    query = parse_qsl(raw_qs, keep_blank_values=True)
    d = evaluate(ep, c.perms.get(ep.id), c, query, path_params)
    if not d.ok:
        return finish(err(403, d.code, d.message, cors))

    # --- upstream so'rovni tayyorlash ---
    headers = {k: v for k, v in request.headers.items() if k.lower() in PASS_REQ_HEADERS}
    binary_ep = "download" in ep.path
    # Har doim JSON so'raymiz: XML/HTML javob maskalashni chetlab o'tmasligi uchun
    headers["Accept"] = "*/*" if binary_ep else "application/json"
    params = list(d.query)
    if ep.auth_mode == "admin":
        if not state.hemis_token:
            return finish(err(503, "no_upstream_token", "Gateway HEMIS tokeni sozlanmagan"))
        headers["Authorization"] = f"Bearer {state.hemis_token}"
    elif ep.auth_mode == "passthrough":
        auth = request.headers.get("authorization", "")
        if auth and not auth[7:].strip().startswith("hg_"):
            headers["Authorization"] = auth
    elif ep.auth_mode == "fast":
        if state.fast_token:
            params.append(("token", state.fast_token))

    base = state.hemis_base if upstream == "hemis" else state.fast_base
    if not base:
        return finish(err(503, "no_upstream", "Upstream manzili sozlanmagan"))

    body = b""
    if method in ("POST", "PUT", "PATCH"):
        body = await request.body()
        if len(body) > MAX_BODY:
            return finish(err(413, "body_too_large", "So'rov hajmi juda katta"))

    # --- kesh ---
    cache_key = None
    if method == "GET" and ep.cache_ttl and ep.auth_mode in ("admin", "public") and not binary_ep:
        lang = request.headers.get("accept-language", "")[:32]
        h = hashlib.sha256(json.dumps([ep.id, path, sorted(d.query), lang]).encode()).hexdigest()
        cache_key = f"cache:{ep.id}:{h}"
        cached = await kv_get_bytes(cache_key)
        if cached:
            if isinstance(cached, str):
                cached = cached.encode()
            ctype, _, content = cached.partition(b"\n")
            return finish(_build_response(200, {"content-type": ctype.decode()}, content, d.hidden_fields,
                                          {**rl_headers, **cors, "X-Cache": "HIT"}), cache_hit=True, upstream_status=200)

    if ep.auth_mode == "admin" and not await upstream_slot(settings.HEMIS_MAX_RPS):
        return finish(err(503, "upstream_busy", "HEMIS band, birozdan keyin urining", {"Retry-After": "1"}))

    try:
        up = await http().request(method, base + path, params=params, headers=headers, content=body or None)
    except httpx.TimeoutException:
        return finish(err(504, "upstream_timeout", "HEMIS javob bermadi (timeout)"))
    except httpx.HTTPError as ex:
        return finish(err(502, "upstream_error", "HEMIS bilan aloqa xatosi"), detail=str(ex)[:500])

    if ep.auth_mode == "admin" and up.status_code in (401, 403):
        # admin token muammosini mijozga oshkor qilmaymiz
        return finish(err(502, "upstream_auth", "Gateway HEMIS bilan avtorizatsiyadan o'ta olmadi"),
                      upstream_status=up.status_code, detail=up.text[:500])

    content = up.content
    is_json = _parse_json(content) is not None
    if not binary_ep and content and not is_json:
        # JSON bo'lmagan javobni maskalab bo'lmaydi — mijozga bermaymiz
        return finish(err(502, "upstream_non_json", "HEMIS kutilmagan formatda javob qaytardi"),
                      upstream_status=up.status_code, detail=up.headers.get("content-type", "")[:100])
    if cache_key and up.status_code == 200 and is_json and len(content) < 5 * 1024 * 1024:
        await kv.set(cache_key, b"application/json\n" + content, ex=ep.cache_ttl)

    resp = _build_response(up.status_code, up.headers, content, d.hidden_fields,
                           {**rl_headers, **cors, "X-Cache": "MISS" if cache_key else "BYPASS"}, binary_ep)
    return finish(resp, upstream_status=up.status_code, bytes=len(content))


def _parse_json(content: bytes):
    if not content:
        return None
    try:
        return json.loads(content)
    except ValueError:
        return None


def _build_response(status: int, up_headers, content: bytes, hidden: list[str], extra: dict,
                    binary: bool = False) -> Response:
    out_headers = {k: v for k, v in (up_headers or {}).items() if k.lower() in PASS_RESP_HEADERS}
    out_headers.update(extra)
    data = _parse_json(content)
    if data is not None:
        data = mask(data, hidden)
        out_headers.pop("content-type", None)
        out_headers.pop("etag", None)
        return Response(json.dumps(data, ensure_ascii=False), status_code=status,
                        media_type="application/json", headers=out_headers)
    if binary or not content:
        return Response(content, status_code=status, headers=out_headers)
    return err(502, "upstream_non_json", "HEMIS kutilmagan formatda javob qaytardi")


@router.get("/gateway/me", tags=["Gateway"])
async def me(request: Request):
    """Mijoz o'z kaliti bilan qaysi endpoint va filtrlarga ruxsati borligini ko'radi."""
    await state.ensure_fresh()
    ip = client_ip(request)
    c, e = await _authenticate(request, ip)
    if e is not None:
        return e
    items = []
    for eid, p in c.perms.items():
        ep = state.endpoints.get(eid)
        if not ep or not ep.is_enabled:
            continue
        qnames = [x["name"] for x in ep.params if x.get("in") == "query"]
        allowed = qnames if p.allowed_params is None else [n for n in qnames if n in p.allowed_params]
        prefix = "/rest" if ep.upstream == "hemis" else "/fast"
        items.append({"method": ep.method, "url": public_base(request) + prefix + ep.path, "group": ep.group,
                      "summary": ep.summary, "allowed_filters": allowed, "locked_filters": p.locked_params or {},
                      "max_limit": p.max_limit, "auth": ep.auth_mode})
    items.sort(key=lambda x: (x["group"], x["url"]))
    return {"success": True, "data": {"client": c.name, "scope": c.scope, "rate_per_second": c.rate_per_second, "rate_per_minute": c.rate_per_minute,
                                      "daily_quota": c.daily_quota, "endpoints": items}}
