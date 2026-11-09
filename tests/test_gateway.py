# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp()
import shutil  # noqa: E402
shutil.copy(os.path.join(os.path.dirname(__file__), "fixtures", "sample-openapi.json"), f"{_tmp}/hemis-openapi.json")
os.environ.update({
    "DATABASE_URL": f"sqlite+aiosqlite:///{_tmp}/t.db", "REDIS_URL": "", "ENV": "development",
    "SECRET_KEY": "test-secret-key-0123456789-abcdefghijkl", "API_KEY_PEPPER": "pep", "INIT_ADMIN_USERNAME": "admin",
    "INIT_ADMIN_PASSWORD": "Admin12345pass", "HEMIS_BASE_URL": "http://hemis/rest",
    "HEMIS_ADMIN_TOKEN": "REAL-HEMIS-ADMIN-TOKEN", "OPENAPI_PATH": f"{_tmp}/hemis-openapi.json",
    "TRUST_PROXY_HEADERS": "true", "SECURITY_LOG": f"{_tmp}/security.log",
})
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402

from app import logwriter, upstream  # noqa: E402
from app.main import app  # noqa: E402
from tests import mock_hemis  # noqa: E402

H = {"X-Requested-With": "hg-admin"}


@pytest_asyncio.fixture(scope="module")
async def ctx():
    async with app.router.lifespan_context(app):
        upstream._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_hemis.app))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
            r = await c.post("/api/admin/auth/login", json={"username": "admin", "password": "Admin12345pass"})
            assert r.status_code == 200, r.text
            c.cookies.set("hg_admin", r.cookies["hg_admin"])
            r = await c.post("/api/admin/security/rules", headers=H, json={"cidr": "127.0.0.1", "action": "allow", "reason": "test"})
            assert r.status_code == 200, r.text
            eps = (await c.get("/api/admin/endpoints")).json()
            ids = {(e["method"], e["path"]): e["id"] for e in eps}
            r = await c.post("/api/admin/clients", headers=H, json={
                "name": "Kimyo fakulteti bot", "scope": {"department": ["7"]}, "rate_per_minute": 1000, "rate_per_second": 0})
            cl = r.json()
            cid, key = cl["client"]["id"], cl["api_key"]
            r = await c.put(f"/api/admin/clients/{cid}/permissions", headers=H, json=[
                {"endpoint_id": ids[("GET", "/v1/data/student-list")], "allowed_params": ["page", "limit", "_group"],
                 "max_limit": 50},
                {"endpoint_id": ids[("GET", "/v1/data/version-info")]},
                {"endpoint_id": ids[("GET", "/v1/account/me")]},
                {"endpoint_id": ids[("GET", "/v1/data/student-stats")],
                 "locked_params": {"group_by": ["level", "gender"]}},
            ])
            assert r.status_code == 200, r.text
            yield {"c": c, "key": key, "cid": cid, "ids": ids, "du": cl["docs_username"], "dp": cl["docs_password"]}


def K(key, **extra):
    return {"X-Gateway-Key": key, **extra}


@pytest.mark.asyncio
async def test_no_key(ctx):
    c = ctx["c"]
    r = await c.get("/rest/v1/data/student-list")
    assert r.status_code == 401
    r = await c.get("/rest/v1/data/student-list", headers=K("hg_0123456789_wrong"))
    assert r.status_code == 401 and r.json()["gateway_code"] == "invalid_key"


@pytest.mark.asyncio
async def test_endpoint_not_allowed(ctx):
    r = await ctx["c"].get("/rest/v1/data/schedule-list", headers=K(ctx["key"]))
    assert r.status_code == 403 and r.json()["gateway_code"] == "endpoint_not_allowed"


@pytest.mark.asyncio
async def test_unknown_endpoint(ctx):
    r = await ctx["c"].get("/rest/v1/data/secret-admin-thing", headers=K(ctx["key"]))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_scope_injected_and_masked(ctx):
    mock_hemis.CALLS.clear()
    r = await ctx["c"].get("/rest/v1/data/student-list?limit=500", headers=K(ctx["key"], Authorization="Bearer hacker"))
    assert r.status_code == 200, r.text
    call = mock_hemis.CALLS[-1]
    assert call["query"]["_department"] == "7"          # doira avtomatik qo'yildi
    assert call["query"]["limit"] == "50"               # max_limit
    assert call["auth"] == "Bearer REAL-HEMIS-ADMIN-TOKEN"  # mijoz headeri almashtirildi
    items = r.json()["data"]["items"]
    assert len(items) == 1 and items[0]["department"]["id"] == 7
    assert "passport_pin" not in items[0] and "phone" not in items[0]   # shaxsiy ma'lumot yashirildi
    assert "REAL-HEMIS" not in r.text


@pytest.mark.asyncio
async def test_bearer_key_works(ctx):
    r = await ctx["c"].get("/rest/v1/data/student-list", headers={"Authorization": f"Bearer {ctx['key']}"})
    assert r.status_code == 200


@pytest.mark.parametrize("qs,code", [
    ("_department=9", "scope_violation"),
    ("search=ali", "param_not_allowed"),
    ("passport_pin=123", "param_not_allowed"),
    ("foo=1", "unknown_param"),
    ("_department[]=9", "unknown_param"),
    ("_group=1&_group=2", "duplicate_param"),
    ("_department=7&_department=9", "duplicate_param"),
])
@pytest.mark.asyncio
async def test_filter_denials(ctx, qs, code):
    r = await ctx["c"].get(f"/rest/v1/data/student-list?{qs}", headers=K(ctx["key"]))
    assert r.status_code == 403, (qs, r.text)
    assert r.json()["gateway_code"] == code


@pytest.mark.asyncio
async def test_scope_unenforceable(ctx):
    r = await ctx["c"].get("/rest/v1/data/version-info", headers=K(ctx["key"]))
    assert r.status_code == 403 and r.json()["gateway_code"] == "scope_unenforceable"


@pytest.mark.asyncio
async def test_locked_params(ctx):
    c, key = ctx["c"], ctx["key"]
    r = await c.get("/rest/v1/data/student-stats", headers=K(key))
    assert r.json()["gateway_code"] == "locked_required"
    r = await c.get("/rest/v1/data/student-stats?group_by=department", headers=K(key))
    assert r.json()["gateway_code"] == "locked_value"
    mock_hemis.CALLS.clear()
    r = await c.get("/rest/v1/data/student-stats?group_by=level", headers=K(key))
    assert r.status_code == 200
    assert mock_hemis.CALLS[-1]["query"] == {"group_by": "level", "_department": "7"}
    r2 = await c.get("/rest/v1/data/student-stats?group_by=level", headers=K(key))
    assert r2.headers["X-Cache"] == "HIT"


@pytest.mark.asyncio
async def test_passthrough_student(ctx):
    mock_hemis.CALLS.clear()
    r = await ctx["c"].get("/rest/v1/account/me", headers=K(ctx["key"], Authorization="Bearer STUDENT-JWT"))
    assert r.status_code == 200
    assert mock_hemis.CALLS[-1]["auth"] == "Bearer STUDENT-JWT"
    assert "passport_pin" not in r.json()["data"] and r.json()["data"]["full_name"] == "Talaba"


@pytest.mark.asyncio
async def test_path_tricks(ctx):
    for p in ["/rest/v1/data/student-list%2F..", "/rest//v1/data/student-list"]:
        r = await ctx["c"].get(p, headers=K(ctx["key"]))
        assert r.status_code in (400, 404), p


@pytest.mark.asyncio
async def test_simulate_and_me(ctx):
    c = ctx["c"]
    r = await c.post(f"/api/admin/clients/{ctx['cid']}/simulate", headers=H,
                     json={"url": "/rest/v1/data/student-list?_department=9"})
    assert r.json()["ok"] is False and r.json()["code"] == "scope_violation"
    r = await c.get("/gateway/me", headers=K(ctx["key"]))
    assert len(r.json()["data"]["endpoints"]) == 4


@pytest.mark.asyncio
async def test_csrf_and_roles(ctx):
    r = await ctx["c"].post("/api/admin/clients", json={"name": "x"})
    assert r.status_code == 403
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as anon:
        assert (await anon.get("/api/admin/clients")).status_code == 401


@pytest.mark.asyncio
async def test_rate_limit_and_disable(ctx):
    c = ctx["c"]
    r = await c.post("/api/admin/clients", headers=H, json={"name": "Limitli", "rate_per_minute": 2,
                                                             "allowed_ips": ["10.0.0.0/8"]})
    cid, key = r.json()["client"]["id"], r.json()["api_key"]
    await c.put(f"/api/admin/clients/{cid}/permissions", headers=H,
                json=[{"endpoint_id": ctx["ids"][("GET", "/v1/data/version-info")]}])
    # IP ruxsat etilmagan
    r = await c.get("/rest/v1/data/version-info", headers=K(key, **{"X-Real-IP": "8.8.8.8"}))
    assert r.json()["gateway_code"] == "ip_not_allowed"
    codes = [(await c.get("/rest/v1/data/version-info", headers=K(key, **{"X-Real-IP": "10.1.2.3"}))).status_code
             for _ in range(3)]
    assert codes == [200, 200, 429]
    # o'chirish
    d = (await c.get(f"/api/admin/clients/{cid}")).json()
    d["is_active"] = False
    await c.put(f"/api/admin/clients/{cid}", headers=H, json={k: d[k] for k in (
        "name", "description", "contact", "is_active", "expires_at", "allowed_ips", "allowed_origins",
        "rate_per_minute", "daily_quota", "scope", "strict_scope", "allow_personal_data")})
    r = await c.get("/rest/v1/data/version-info", headers=K(key, **{"X-Real-IP": "10.1.2.3"}))
    assert r.json()["gateway_code"] == "client_disabled"
    # kalit almashtirish -> eski kalit ishlamaydi
    new = (await c.post(f"/api/admin/clients/{cid}/rotate-key", headers=H)).json()["api_key"]
    r = await c.get("/rest/v1/data/version-info", headers=K(key))
    assert r.json()["gateway_code"] == "invalid_key"
    assert new != key


@pytest.mark.asyncio
async def test_logs_and_monitor(ctx):
    c = ctx["c"]
    await logwriter.drain()
    r = await c.get("/api/admin/logs?status=denied")
    assert r.json()["total"] > 5
    m = (await c.get("/api/admin/monitor/summary?hours=24")).json()
    assert m["total"] > 10 and m["denied"] > 5 and m["deny_reasons"]
    s = (await c.get("/api/admin/stats/students?group_by=gender")).json()
    assert s["result"]["data"]["total"] == 5230
    r = await c.get("/api/admin/stats/students?group_by=hack")
    assert r.status_code == 400


def test_policy_fast_scope_and_path_lock():
    from types import SimpleNamespace as NS
    from app.policy import evaluate
    cl = NS(scope={"department": ["7"]}, strict_scope=True, allow_personal_data=False)
    perm = NS(allowed_params=None, locked_params={"id": ["5"]}, max_limit=None, hidden_fields=[], allow_personal=False)
    nolock = NS(allowed_params=None, locked_params={}, max_limit=None, hidden_fields=[], allow_personal=False)
    fast = NS(params=[], auth_mode="fast")
    assert evaluate(fast, nolock, cl, []).code == "scope_unenforceable"
    stu = NS(params=[], auth_mode="passthrough")
    assert evaluate(stu, nolock, cl, []).ok
    assert evaluate(stu, perm, cl, []).code == "locked_param_missing"   # qulf yo'qolgan filtrga -> rad
    ep = NS(params=[{"name": "id", "in": "path"}], auth_mode="passthrough")
    assert evaluate(ep, perm, cl, [], {"id": "6"}).code == "locked_value"
    assert evaluate(ep, perm, cl, [], {"id": "5"}).ok


@pytest.mark.asyncio
async def test_upstream_accept_forced_json(ctx):
    mock_hemis.CALLS.clear()
    await ctx["c"].get("/rest/v1/data/student-list?_group=45", headers=K(ctx["key"], Accept="application/xml"))
    # mock CALLS doesn't record accept; check via direct header echo is not available -> ensure JSON returned
    r = await ctx["c"].get("/rest/v1/data/student-list?_group=46", headers=K(ctx["key"], Accept="application/xml"))
    assert r.headers["content-type"].startswith("application/json")


@pytest.mark.asyncio
async def test_docs_swagger(ctx):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as d:
        r = await d.get("/docs")
        assert "docs-login.js" in r.text
        assert (await d.get("/docs/openapi.json")).status_code == 401
        DH = {"X-Requested-With": "hg-docs"}
        r = await d.post("/docs/login", headers=DH, json={"username": ctx["du"], "password": "wrong"})
        assert r.status_code == 401
        r = await d.post("/docs/login", json={"username": ctx["du"], "password": ctx["dp"]})
        assert r.status_code == 403  # CSRF header yo'q
        r = await d.post("/docs/login", headers=DH, json={"username": ctx["du"].upper(), "password": ctx["dp"]})
        assert r.status_code == 200, r.text
        d.cookies.set("hg_docs", r.cookies["hg_docs"], path="/docs")
        assert "swagger-ui-bundle.js" in (await d.get("/docs")).text
        spec = (await d.get("/docs/openapi.json")).json()
        assert set(spec["paths"]) == {"/v1/data/student-list", "/v1/data/version-info", "/v1/account/me", "/v1/data/student-stats"}
        sl = {p["name"]: p for p in spec["paths"]["/v1/data/student-list"]["get"]["parameters"]}
        assert set(sl) == {"page", "limit", "_group", "_department"}      # faqat ruxsat + doira filtri
        assert sl["_department"]["schema"]["enum"] == ["7"] and sl["limit"]["schema"]["maximum"] == 50
        gb = [p for p in spec["paths"]["/v1/data/student-stats"]["get"]["parameters"] if p["name"] == "group_by"][0]
        assert gb["schema"]["enum"] == ["level", "gender"] and gb["required"] is True
        assert spec["paths"]["/v1/account/me"]["get"]["security"] == [{"gatewayKey": [], "userBearer": []}]
        assert "passport_pin" in spec["paths"]["/v1/data/student-list"]["get"]["description"]
        # admin parolni yangilasa — sessiya bekor bo'ladi
        r = await ctx["c"].post(f"/api/admin/clients/{ctx['cid']}/docs-password", headers=H)
        assert r.status_code == 200 and r.json()["docs_password"] != ctx["dp"]
        assert (await d.get("/docs/openapi.json")).status_code == 401


@pytest.mark.asyncio
async def test_rate_per_second(ctx):
    c = ctx["c"]
    r = await c.post("/api/admin/clients", headers=H, json={"name": "Tezkor", "rate_per_second": 3, "rate_per_minute": 1000})
    cid, key = r.json()["client"]["id"], r.json()["api_key"]
    await c.put(f"/api/admin/clients/{cid}/permissions", headers=H,
                json=[{"endpoint_id": ctx["ids"][("GET", "/v1/data/version-info")]}])
    import time
    while time.time() % 1 > 0.6:   # bitta soniya ichiga sig'dirish
        time.sleep(0.05)
    codes = [(await c.get("/rest/v1/data/version-info", headers=K(key))).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429
    r = await c.get("/rest/v1/data/version-info", headers=K(key))
    assert r.headers.get("Retry-After") == "1" or r.status_code == 200


# ======================= XAVFSIZLIK =======================
import asyncio  # noqa: E402

from app import guard as _guard  # noqa: E402


async def _settle():
    await asyncio.sleep(0.15)


@pytest.mark.asyncio
async def test_auto_ban_and_unban(ctx, monkeypatch):
    c = ctx["c"]
    sent = []

    async def fake_tg(text, token=None, chat_id=None):
        sent.append(text)
        return True, ""
    monkeypatch.setattr(_guard, "send_telegram", fake_tg)
    r = await c.put("/api/admin/security/settings", headers=H, json={
        "abuse_threshold": "5", "abuse_window": "300", "ban_steps": "900,3600", "telegram_chat_id": "-100",
        "telegram_bot_token": "x:y", "alerts_enabled": "1"})
    assert r.status_code == 200, r.text
    ip = {"X-Real-IP": "7.7.7.7"}
    for _ in range(6):
        await c.get("/rest/v1/data/student-list", headers={**ip, "X-Gateway-Key": "hg_0000000000_bad"})
        await _settle()
    r = await c.get("/rest/v1/data/student-list", headers={**ip, "X-Gateway-Key": ctx["key"]})
    assert r.status_code == 403 and r.json()["gateway_code"] == "ip_blocked"
    # docs va admin ham yopiq
    assert (await c.get("/docs", headers=ip)).status_code == 403
    rules = (await c.get("/api/admin/security/rules")).json()
    rule = next(x for x in rules if x["cidr"] == "7.7.7.7")
    assert rule["auto"] and rule["active"]
    from pathlib import Path
    from app.config import settings as S
    assert "BAN ip=7.7.7.7" in Path(S.SECURITY_LOG).read_text()
    await _settle()
    assert any("7.7.7.7" in t for t in sent)          # Telegram ogohlantirish
    ev = (await c.get("/api/admin/security/events?type=ip_banned")).json()
    assert ev["total"] >= 1
    assert (await c.delete(f"/api/admin/security/rules/{rule['id']}", headers=H)).status_code == 200
    r = await c.get("/rest/v1/data/student-list", headers={**ip, "X-Gateway-Key": ctx["key"]})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_allow_and_area_rules(ctx):
    c = ctx["c"]
    await c.post("/api/admin/security/rules", headers=H, json={"cidr": "8.8.4.0/24", "action": "allow"})
    for _ in range(12):
        await c.get("/rest/v1/data/student-list", headers={"X-Real-IP": "8.8.4.4", "X-Gateway-Key": "hg_0000000000_bad"})
    await _settle()
    r = await c.get("/rest/v1/data/student-list", headers={"X-Real-IP": "8.8.4.4", "X-Gateway-Key": ctx["key"]})
    assert r.status_code == 200                         # ishonchli IP ban qilinmaydi
    r = await c.post("/api/admin/security/rules", headers=H, json={"cidr": "9.9.9.9", "area": "gateway", "minutes": 60})
    assert r.status_code == 200
    assert (await c.get("/rest/v1/data/student-list", headers={"X-Real-IP": "9.9.9.9", "X-Gateway-Key": ctx["key"]})).status_code == 403
    assert (await c.get("/docs", headers={"X-Real-IP": "9.9.9.9"})).status_code == 200
    r = await c.post("/api/admin/security/rules", headers=H, json={"cidr": "127.0.0.0/24", "action": "block"})
    assert r.status_code == 400                         # o'zini bloklay olmaydi
    r = await c.post("/api/admin/security/rules", headers=H, json={"cidr": "0.0.0.0/0", "action": "block"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_key_theft_suspend(ctx):
    c = ctx["c"]
    r = await c.post("/api/admin/clients", headers=H, json={"name": "O'g'irlangan", "max_distinct_ips": 2,
                                                             "rate_per_second": 0})
    cid, key = r.json()["client"]["id"], r.json()["api_key"]
    await c.put(f"/api/admin/clients/{cid}/permissions", headers=H,
                json=[{"endpoint_id": ctx["ids"][("GET", "/v1/data/version-info")]}])
    for ip in ["31.1.1.1", "31.1.1.2", "31.1.1.3"]:
        await c.get("/rest/v1/data/version-info", headers={"X-Real-IP": ip, "X-Gateway-Key": key})
        await _settle()
    r = await c.get("/rest/v1/data/version-info", headers={"X-Real-IP": "31.1.1.1", "X-Gateway-Key": key})
    assert r.json()["gateway_code"] == "client_suspended"
    d = (await c.get(f"/api/admin/clients/{cid}")).json()
    assert d["suspended_until"] and "IP" in d["suspend_reason"]
    assert (await c.post(f"/api/admin/security/clients/{cid}/resume", headers=H)).status_code == 200
    r = await c.get("/rest/v1/data/version-info", headers={"X-Real-IP": "31.1.1.1", "X-Gateway-Key": key})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_captcha_docs_login(ctx, monkeypatch):
    from app import captcha
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as d:
        DH = {"X-Requested-With": "hg-docs", "X-Real-IP": "5.5.5.5"}
        await ctx["c"].post("/api/admin/security/rules", headers=H, json={"cidr": "5.5.5.5", "action": "allow"})
        for _ in range(3):
            r = await d.post("/docs/login", headers=DH, json={"username": "nobody", "password": "x"})
            assert r.status_code == 401
        r = await d.post("/docs/login", headers=DH, json={"username": "nobody", "password": "x"})
        assert r.status_code == 428
        monkeypatch.setattr(captcha, "ALPHABET", "A")
        cap = (await d.get("/api/captcha", headers=DH)).json()
        assert cap["image"].startswith("data:image/png;base64,")
        r = await d.post("/docs/login", headers=DH, json={"username": "nobody", "password": "x",
                                                         "captcha_id": cap["captcha_id"], "captcha": "aaaaa"})
        assert r.status_code == 401                     # captcha o'tdi, parol noto'g'ri
        r = await d.post("/docs/login", headers=DH, json={"username": "nobody", "password": "x",
                                                         "captcha_id": cap["captcha_id"], "captcha": "AAAAA"})
        assert r.status_code == 428                     # captcha bir martalik


def _xlsx(rows):
    import io
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    for r in rows:
        ws.append(r)
    b = io.BytesIO()
    wb.save(b)
    return b.getvalue()


@pytest.mark.asyncio
async def test_excel_block_import_export(ctx):
    import io
    from datetime import datetime, timedelta
    from openpyxl import load_workbook
    c = ctx["c"]
    future = (datetime.now() + timedelta(days=3)).strftime("%d.%m.%Y %H:%M")
    data = _xlsx([
        ["IP / tarmoq", "Qayerga", "Tugash vaqti", "Sabab"],
        ["44.44.44.44", "hammasi", "doimiy", "skaner"],
        ["44.44.45.0/24", "gateway", future, "bot tarmog'i"],
        ["44.44.46.1", "", "7 kun", ""],
        ["noto'g'ri-ip", "hammasi", "", ""],
        ["44.44.44.47", "kosmos", "", ""],
        ["44.44.44.48", "hammasi", "01.01.2020", ""],
        ["127.0.0.1", "admin", "", "o'zimni"],
        ["44.44.44.44", "hammasi", "", "takror"],
        ["10.0.0.0/4", "", "", "juda keng"],
    ])
    f = {"file": ("q.xlsx", data, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
    r = await c.post("/api/admin/security/lists/block/import", headers=H, files=f, data={"mode": "merge", "dry_run": "true"})
    res = r.json()
    assert r.status_code == 200, r.text
    assert res["dry_run"] and res["added"] == 3 and res["error_count"] == 5 and res["warning_count"] == 1
    assert {e["row"] for e in res["errors"]} == {5, 6, 7, 8, 10}
    # dry-run hech narsa yozmaydi
    assert (await c.get("/rest/v1/data/student-list", headers={"X-Real-IP": "44.44.44.44", "X-Gateway-Key": ctx["key"]})).status_code == 200
    r = await c.post("/api/admin/security/lists/block/import", headers=H, files=f, data={"mode": "merge"})
    assert r.json()["added"] == 3
    for ip, path, code in [("44.44.44.44", "/docs", 403), ("44.44.45.9", "/rest/v1/data/student-list", 403),
                           ("44.44.45.9", "/docs", 200), ("44.44.46.1", "/docs", 403)]:
        rr = await c.get(path, headers={"X-Real-IP": ip, "X-Gateway-Key": ctx["key"]})
        assert rr.status_code == code, (ip, path, rr.status_code)
    # eksport -> o'qish
    r = await c.get("/api/admin/security/lists/block/export")
    assert r.status_code == 200 and "spreadsheetml" in r.headers["content-type"]
    ws = load_workbook(io.BytesIO(r.content)).worksheets[0]
    vals = {row[0]: row for row in ws.iter_rows(min_row=2, values_only=True)}
    assert "44.44.45.0/24" in vals and vals["44.44.45.0/24"][1] == "gateway" and vals["44.44.44.44"][2] == "doimiy"
    # eksport faylini qayta import (round-trip) — hammasi "yangilanadi"
    r = await c.post("/api/admin/security/lists/block/import", headers=H, data={"mode": "merge", "dry_run": "true"},
                     files={"file": ("e.xlsx", r.content, "application/octet-stream")})
    assert r.json()["added"] == 0 and r.json()["updated"] >= 3 and r.json()["error_count"] == 0
    # almashtirish: faqat bittasi qoladi
    r = await c.post("/api/admin/security/lists/block/import", headers=H, data={"mode": "replace"},
                     files={"file": ("r.xlsx", _xlsx([["IP / tarmoq"], ["44.44.44.44"]]), "x")})
    assert r.json()["removed"] >= 2
    assert (await c.get("/docs", headers={"X-Real-IP": "44.44.46.1"})).status_code == 200
    # shablon
    r = await c.get("/api/admin/security/lists/allow/template")
    wb = load_workbook(io.BytesIO(r.content))
    assert wb.sheetnames == ["Oq ro'yxat", "Yo'riqnoma"]


@pytest.mark.asyncio
async def test_excel_allow_import_and_bulk_delete(ctx):
    c = ctx["c"]
    data = _xlsx([["Sabab", "IP / tarmoq"], ["hamkor", "66.66.66.0/24"], ["server", "66.66.67.5"]])  # ustunlar tartibi boshqa
    r = await c.post("/api/admin/security/lists/allow/import", headers=H, data={"mode": "merge"},
                     files={"file": ("a.xlsx", data, "x")})
    assert r.json()["added"] == 2, r.text
    for _ in range(60):
        await c.get("/rest/v1/data/x", headers={"X-Real-IP": "66.66.66.10", "X-Gateway-Key": "hg_0000000000_bad"})
    await _settle()
    assert (await c.get("/docs", headers={"X-Real-IP": "66.66.66.10"})).status_code == 200   # oq ro'yxat — ban yo'q
    rules = [x for x in (await c.get("/api/admin/security/rules")).json() if x["cidr"].startswith("66.66.")]
    r = await c.post("/api/admin/security/lists/allow/bulk-delete", headers=H, json={"ids": [x["id"] for x in rules]})
    assert r.json()["deleted"] == 2
    r = await c.post("/api/admin/security/lists/allow/import", headers=H, data={"mode": "merge"},
                     files={"file": ("bad.xlsx", b"not excel", "x")})
    assert r.status_code == 400
    r = await c.post("/api/admin/security/lists/allow/import", headers=H, data={"mode": "merge"},
                     files={"file": ("h.xlsx", _xlsx([["Manzil"], ["1.1.1.1"]]), "x")})
    assert r.status_code == 400 and "sarlavha" in r.json()["detail"]


# ======================= HEMIS docs yangilash =======================

@pytest.mark.asyncio
async def test_spec_update_flow(ctx):
    import copy
    import json as _json
    from pathlib import Path
    from app.config import settings as S
    c = ctx["c"]
    orig_raw = Path(S.OPENAPI_PATH).read_bytes()
    spec = _json.loads(orig_raw)
    new = copy.deepcopy(spec)
    # 1) endpoint olib tashlanadi, 2) yangi endpoint, 3) student-stats dan group_by (qulflangan!) olib tashlanadi,
    # 4) student-list ga yangi filtr qo'shiladi
    del new["paths"]["/v1/account/me"]
    new["paths"]["/v1/data/brand-new-report"] = {"get": {"tags": ["1. Backend API"], "summary": "Yangi hisobot",
                                                         "parameters": [{"name": "_department", "in": "query"}],
                                                         "responses": {"200": {"description": "OK"}}}}
    ps = new["paths"]["/v1/data/student-stats"]["get"]["parameters"]
    new["paths"]["/v1/data/student-stats"]["get"]["parameters"] = [p for p in ps if p.get("name") != "group_by"]
    new["paths"]["/v1/data/student-list"]["get"]["parameters"].append({"name": "_new_filter", "in": "query"})
    new["info"]["version"] = "9.9"
    raw = _json.dumps(new).encode()
    f = lambda: {"file": ("docs.json", raw, "application/json")}  # noqa: E731

    d = (await c.post("/api/admin/spec/preview", headers=H, files=f())).json()
    assert d["info"]["version"] == "9.9"
    assert [x["path"] for x in d["added"]] == ["/v1/data/brand-new-report"]
    assert [x["path"] for x in d["removed"]] == ["/v1/account/me"] and d["removed"][0]["clients"]
    ch = {x["path"]: x for x in d["changed"]}
    assert ch["/v1/data/student-stats"]["params_removed"] == ["group_by"]
    assert ch["/v1/data/student-list"]["params_added"] == ["_new_filter"]
    msgs = " | ".join(i["message"] for i in d["impacts"])
    assert "qulflangan filtr" in msgs and "olib tashlanadi" in msgs
    assert not d["large_removal"]
    # preview hech narsa o'zgartirmaydi
    assert (await c.get("/rest/v1/account/me", headers=K(ctx["key"], Authorization="Bearer STUDENT-JWT"))).status_code == 200

    r = await c.post("/api/admin/spec/apply", headers=H, files=f())
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["added"] == 1 and res["removed"] == 1
    # olib tashlangan endpoint -> 410, docs da yo'q
    r = await c.get("/rest/v1/account/me", headers=K(ctx["key"], Authorization="Bearer STUDENT-JWT"))
    assert r.status_code == 410 and r.json()["gateway_code"] == "endpoint_removed"
    # qulflangan filtr yo'qoldi -> fail-closed
    r = await c.get("/rest/v1/data/student-stats", headers=K(ctx["key"]))
    assert r.status_code == 403 and r.json()["gateway_code"] == "locked_param_missing"
    # yangi endpoint mijozga avtomatik ochilmaydi
    r = await c.get("/rest/v1/data/brand-new-report", headers=K(ctx["key"]))
    assert r.json()["gateway_code"] == "endpoint_not_allowed"
    eps = {(e["method"], e["path"]): e for e in (await c.get("/api/admin/endpoints")).json()}
    assert eps[("GET", "/v1/account/me")]["in_spec"] is False
    assert eps[("GET", "/v1/data/brand-new-report")]["params"][0]["scope_key"] == "department"

    # versiyalar: kamida 2 ta (boshlang'ich + yangi), yangi — joriy
    v = (await c.get("/api/admin/spec/versions")).json()["versions"]
    assert len(v) >= 2 and v[0]["current"] and v[0]["version"] == "9.9"
    old = next(x for x in v if not x["current"])
    # rollback: eski versiyaga qaytish
    r = await c.post("/api/admin/spec/apply", headers=H, data={"version": old["name"]})
    assert r.status_code == 200 and r.json()["restored"] == 1
    r = await c.get("/rest/v1/account/me", headers=K(ctx["key"], Authorization="Bearer STUDENT-JWT"))
    assert r.status_code == 200
    r = await c.get("/rest/v1/data/student-stats?group_by=level", headers=K(ctx["key"]))
    assert r.status_code == 200
    assert Path(S.OPENAPI_PATH).read_bytes() == orig_raw


@pytest.mark.asyncio
async def test_spec_bad_and_large_removal(ctx):
    import json as _json
    c = ctx["c"]
    r = await c.post("/api/admin/spec/preview", headers=H, files={"file": ("x.json", b"{not json", "x")})
    assert r.status_code == 400
    r = await c.post("/api/admin/spec/preview", headers=H, files={"file": ("x.json", b'{"a": 1}', "x")})
    assert r.status_code == 400
    tiny = {"openapi": "3.0.0", "info": {"version": "0"}, "paths": {"/v1/data/version-info": {"get": {
        "tags": ["1. Backend API"], "responses": {"200": {"description": "OK"}}}}}}
    raw = _json.dumps(tiny).encode()
    d = (await c.post("/api/admin/spec/preview", headers=H, files={"file": ("t.json", raw, "x")})).json()
    assert d["large_removal"] is True
    r = await c.post("/api/admin/spec/apply", headers=H, files={"file": ("t.json", raw, "x")})
    assert r.status_code == 409       # tasdiqsiz qo'llanmaydi


@pytest.mark.asyncio
async def test_auto_sync_modes(ctx):
    import copy
    import json as _json
    from pathlib import Path
    from app import spec_update
    from app.config import settings as S
    c = ctx["c"]
    spec_update._transport = httpx.ASGITransport(app=mock_hemis.app)
    orig = _json.loads(Path(S.OPENAPI_PATH).read_bytes())
    try:
        # 1) URL ni avtomatik topish (HEMIS_BASE_URL=http://hemis/rest)
        mock_hemis.SPEC.clear(); mock_hemis.SPEC.update(orig)
        r = (await c.post("/api/admin/spec/discover", headers=H)).json()
        assert r["found"] == "http://hemis/rest/docs.json", r
        await c.put("/api/admin/spec/sync", headers=H, json={"url": "", "mode": "safe", "hours": 6, "new_filters": "freeze"})
        r = (await c.post("/api/admin/spec/check-now", headers=H)).json()
        assert r["status"] == "same", r            # URL bo'sh — o'zi topdi, o'zgarish yo'q
        assert (await c.get("/api/admin/spec/sync")).json()["url"] == "http://hemis/rest/docs.json"

        # 2) xavfsiz o'zgarish: yangi endpoint + student-stats ga yangi filtr -> avtomatik qo'llanadi, ruxsat qotiriladi
        s2 = copy.deepcopy(orig)
        s2["paths"]["/v1/data/auto-new"] = {"get": {"tags": ["1. Backend API"], "summary": "Avto",
                                                    "responses": {"200": {"description": "OK"}}}}
        s2["paths"]["/v1/data/student-stats"]["get"]["parameters"].append({"name": "_secret_filter", "in": "query"})
        mock_hemis.SPEC.clear(); mock_hemis.SPEC.update(s2)
        r = (await c.post("/api/admin/spec/check-now", headers=H)).json()
        assert r["status"] == "applied", r
        r = await c.get("/rest/v1/data/student-stats?group_by=level&_secret_filter=1", headers=K(ctx["key"]))
        assert r.json()["gateway_code"] == "param_not_allowed"   # yangi filtr «barcha filtrlar» mijozga berilmadi
        assert (await c.get("/rest/v1/data/student-stats?group_by=level", headers=K(ctx["key"]))).status_code == 200

        # 3) xavfli o'zgarish (ishlatilayotgan endpoint yo'qoladi) — safe rejimda qo'llanmaydi
        s3 = copy.deepcopy(s2)
        del s3["paths"]["/v1/account/me"]
        mock_hemis.SPEC.clear(); mock_hemis.SPEC.update(s3)
        r = (await c.post("/api/admin/spec/check-now", headers=H)).json()
        assert r["status"] == "pending" and "Tasdiq kerak" in r["message"], r
        assert (await c.get("/rest/v1/account/me", headers=K(ctx["key"], Authorization="Bearer STUDENT-JWT"))).status_code == 200
        ev = (await c.get("/api/admin/security/events?type=spec_changed")).json()
        assert ev["total"] >= 1

        # 4) full rejim — qo'llanadi
        await c.put("/api/admin/spec/sync", headers=H, json={"url": "http://hemis/rest/docs.json", "mode": "full",
                                                             "hours": 1, "new_filters": "freeze"})
        r = (await c.post("/api/admin/spec/check-now", headers=H)).json()
        assert r["status"] == "applied" and "Diqqat" in r["message"], r
        assert (await c.get("/rest/v1/account/me", headers=K(ctx["key"], Authorization="Bearer STUDENT-JWT"))).status_code == 410

        # 5) URL ishlamasa — xato holati
        await c.put("/api/admin/spec/sync", headers=H, json={"url": "http://hemis/rest/none.json", "mode": "safe",
                                                             "hours": 6, "new_filters": "freeze"})
        r = (await c.post("/api/admin/spec/check-now", headers=H)).json()
        assert r["status"] == "error"
    finally:
        mock_hemis.SPEC.clear(); mock_hemis.SPEC.update(orig)
        await c.put("/api/admin/spec/sync", headers=H, json={"url": "http://hemis/rest/docs.json", "mode": "full",
                                                             "hours": 6, "new_filters": "allow"})
        await c.post("/api/admin/spec/check-now", headers=H)
        await c.put("/api/admin/spec/sync", headers=H, json={"url": "", "mode": "off", "hours": 6, "new_filters": "freeze"})
        spec_update._transport = None



@pytest.mark.asyncio
async def test_spec_password_protected_docs(ctx):
    import json as _json
    from pathlib import Path
    from app import spec_update
    from app.config import settings as S
    c = ctx["c"]
    spec_update._transport = httpx.ASGITransport(app=mock_hemis.app)
    orig = _json.loads(Path(S.OPENAPI_PATH).read_bytes())
    mock_hemis.SPEC.clear(); mock_hemis.SPEC.update(orig)
    mock_hemis.SPEC_PASSWORD["value"] = "sirli-parol"
    try:
        r = (await c.post("/api/admin/spec/discover", headers=H)).json()
        assert r["found"] == "http://hemis/rest/docs.json" and "parol" in r["tried"][-1]["result"]
        base = {"url": "http://hemis/rest/docs.json", "mode": "safe", "hours": 6, "new_filters": "freeze"}
        await c.put("/api/admin/spec/sync", headers=H, json={**base, "password": "-"})
        r = (await c.post("/api/admin/spec/check-now", headers=H)).json()
        assert r["status"] == "error" and "parol bilan himoyalangan" in r["message"], r
        await c.put("/api/admin/spec/sync", headers=H, json={**base, "password": "xato"})
        r = (await c.post("/api/admin/spec/check-now", headers=H)).json()
        assert r["status"] == "error" and "noto'g'ri" in r["message"], r
        await c.put("/api/admin/spec/sync", headers=H, json={**base, "password": "sirli-parol"})
        assert (await c.get("/api/admin/spec/sync")).json()["password_set"] is True
        r = (await c.post("/api/admin/spec/check-now", headers=H)).json()
        assert r["status"] == "same", r          # parol bilan kirdi va hujjatni oldi
    finally:
        mock_hemis.SPEC_PASSWORD["value"] = ""
        await c.put("/api/admin/spec/sync", headers=H, json={"url": "", "mode": "off", "hours": 6,
                                                             "new_filters": "freeze", "password": "-"})
        spec_update._transport = None


@pytest.mark.asyncio
async def test_upstream_404_not_counted_as_abuse(ctx):
    from app.kv import kv
    c = ctx["c"]
    r = await c.post("/api/admin/clients", headers=H, json={"name": "Lookup", "rate_per_second": 0})
    cid, key = r.json()["client"]["id"], r.json()["api_key"]
    await c.put(f"/api/admin/clients/{cid}/permissions", headers=H,
                json=[{"endpoint_id": ctx["ids"][("GET", "/v1/data/student-info")]}])
    ip = {"X-Real-IP": "55.1.1.1", "X-Gateway-Key": key}
    for _ in range(5):
        r = await c.get("/rest/v1/data/student-info?student_id_number=0", headers=ip)
        assert r.status_code == 404                 # HEMIS ning o'z javobi
    await asyncio.sleep(0.2)
    assert not await kv.get("abuse:55.1.1.1")       # HEMIS 404 lari ban hisobiga kirmaydi
    await c.get("/rest/v1/data/student-info?hack=1", headers=ip)   # gateway rad etishi
    await asyncio.sleep(0.2)
    assert int(await kv.get("abuse:55.1.1.1") or 0) == 1


@pytest.mark.asyncio
async def test_settings_test_connection_with_form_token(ctx):
    from app.branding import clean_token
    assert clean_token('  "Bearer abc 123"\n') == "abc123"
    c = ctx["c"]
    # formadagi noto'g'ri token — 401 va aniq tavsiya
    r = (await c.post("/api/admin/settings/test", headers=H, json={"hemis_admin_token": "WRONG"})).json()
    assert r["ok"] is False and r["status"] == 401 and "API User" in r["hint"]
    assert r["diag"]["token_source"].startswith("formadagi")
    # formadagi to'g'ri token (Bearer prefiksi bilan nusxalangan bo'lsa ham) — saqlamasdan tekshiradi
    r = (await c.post("/api/admin/settings/test", headers=H, json={"hemis_admin_token": "Bearer REAL-HEMIS-ADMIN-TOKEN "})).json()
    assert r["ok"] is True and "Saqlash" in r["hint"]
    # bo'sh forma — saqlangan (env) token ishlatiladi
    r = (await c.post("/api/admin/settings/test", headers=H, json={})).json()
    assert r["ok"] is True and r["diag"]["token_source"]


@pytest.mark.asyncio
async def test_setup_full_sync_from_empty(ctx, monkeypatch):
    """Bo'sh katalogdan: token + docs (parol bilan) + profil bir bosishda."""
    import json as _json
    from pathlib import Path
    from app import branding, spec_update
    from app.config import settings as S
    c = ctx["c"]
    spec_update._transport = httpx.ASGITransport(app=mock_hemis.app)
    orig = _json.loads(Path(S.OPENAPI_PATH).read_bytes())
    mock_hemis.SPEC.clear(); mock_hemis.SPEC.update(orig)
    mock_hemis.SPEC_PASSWORD["value"] = "docs-pw"

    async def fake_profile(save=True):
        return {"name": "Namuna universiteti", "code": "999", "region": "Toshkent"}
    monkeypatch.setattr("app.setup_api.fetch_university_profile", fake_profile)
    try:
        await c.put("/api/admin/spec/sync", headers=H, json={"url": "", "mode": "safe", "hours": 6,
                                                             "new_filters": "freeze", "password": "-"})
        r = (await c.post("/api/admin/setup/sync", headers=H, json={"hemis_admin_token": "REAL-HEMIS-ADMIN-TOKEN"})).json()
        st = {x["key"]: x for x in r["steps"]}
        assert st["token"]["ok"] and st["profile"]["ok"]
        assert st["docs"]["ok"] is False and st["docs"].get("need_password")      # parol so'radi
        r = (await c.post("/api/admin/setup/sync", headers=H, json={"docs_password": "docs-pw"})).json()
        st = {x["key"]: x for x in r["steps"]}
        assert r["ok"] and st["docs"]["ok"], r
        b = (await c.get("/api/public/branding")).json()
        assert b["org_name"]       # OTM nomi to'ldirilgan
        assert (await c.get("/api/admin/settings")).json()["docs_password_set"] is True
    finally:
        mock_hemis.SPEC_PASSWORD["value"] = ""
        await c.put("/api/admin/spec/sync", headers=H, json={"url": "", "mode": "off", "hours": 6,
                                                             "new_filters": "freeze", "password": "-"})
        spec_update._transport = None
