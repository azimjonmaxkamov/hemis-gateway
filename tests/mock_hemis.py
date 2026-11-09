# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Test va demo uchun soxta HEMIS server."""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
TOKEN = "REAL-HEMIS-ADMIN-TOKEN"
CALLS: list[dict] = []


def _auth_ok(request: Request):
    return request.headers.get("authorization") == f"Bearer {TOKEN}"


@app.get("/rest/v1/data/student-list")
async def students(request: Request):
    CALLS.append({"path": request.url.path, "query": dict(request.query_params), "auth": request.headers.get("authorization")})
    if not _auth_ok(request):
        return JSONResponse({"success": False, "error": "Unauthorized", "code": 401}, status_code=401)
    dep = request.query_params.get("_department")
    items = [
        {"id": 1, "full_name": "Aliyev Vali", "passport_pin": "31234567890123", "phone": "+998901234567",
         "department": {"id": 7, "name": "Kimyo"}, "group": {"id": 45, "name": "K-21"}},
        {"id": 2, "full_name": "Karimova Laylo", "passport_pin": "41234567890123", "phone": "+998911112233",
         "department": {"id": 9, "name": "Iqtisod"}, "group": {"id": 50, "name": "I-22"}},
    ]
    if dep:
        items = [i for i in items if str(i["department"]["id"]) == dep]
    return {"success": True, "error": None, "data": {"items": items, "pagination": {"totalCount": len(items)}}}


@app.get("/rest/v1/data/student-stats")
async def stats(request: Request):
    CALLS.append({"path": request.url.path, "query": dict(request.query_params)})
    gb = request.query_params.get("group_by", "education_form")
    return {"success": True, "data": {"group_by": gb, "total": 5230, "items": [
        {"code": "11", "name": "Kunduzgi", "count": 4100, "percent": 78.4},
        {"code": "13", "name": "Sirtqi", "count": 830, "percent": 15.9},
        {"code": "15", "name": "Kechki", "count": 300, "percent": 5.7}]}}


@app.get("/rest/v1/data/version-info")
async def ver(request: Request):
    if not _auth_ok(request):
        return JSONResponse({"success": False, "error": "Your request was made with invalid credentials.",
                             "data": [], "code": 401}, status_code=401)
    return {"success": True, "data": {"version": "3.x", "university": "TEST"}}


@app.get("/rest/v1/account/me")
async def me(request: Request):
    CALLS.append({"path": request.url.path, "auth": request.headers.get("authorization")})
    if request.headers.get("authorization") == "Bearer STUDENT-JWT":
        return {"success": True, "data": {"full_name": "Talaba", "passport_pin": "3000", "email": "t@x.uz"}}
    return JSONResponse({"success": False, "code": 401}, status_code=401)


@app.get("/rest/v1/data/schedule-list")
async def sched(request: Request):
    CALLS.append({"path": request.url.path, "query": dict(request.query_params)})
    return {"success": True, "data": {"items": []}}


SPEC: dict = {}


SPEC_PASSWORD = {"value": ""}
_FORM = """<!DOCTYPE html><html><body><h1>Swagger Documentation</h1>
<form action="/rest/docs" method="post"><input type="hidden" name="_csrf" value="tok123">
<input type="password" name="swagger_password"><button type="submit">Kirish</button></form></body></html>"""


@app.get("/rest/docs.json")
async def docs_json(request: Request):
    from fastapi.responses import HTMLResponse
    if SPEC_PASSWORD["value"] and request.cookies.get("docs_ok") != "1":
        return HTMLResponse(_FORM, status_code=401)
    if not SPEC:
        return JSONResponse({"error": "no"}, status_code=404)
    return SPEC


@app.post("/rest/docs")
async def docs_login(request: Request):
    from fastapi.responses import HTMLResponse, RedirectResponse
    form = await request.form()
    if form.get("_csrf") == "tok123" and form.get("swagger_password") == SPEC_PASSWORD["value"]:
        r = RedirectResponse("/rest/docs", status_code=302)
        r.set_cookie("docs_ok", "1")
        return r
    return HTMLResponse(_FORM, status_code=401)


@app.get("/rest/docs")
async def docs_page(request: Request):
    from fastapi.responses import HTMLResponse
    if SPEC_PASSWORD["value"] and request.cookies.get("docs_ok") != "1":
        return HTMLResponse(_FORM, status_code=401)
    return HTMLResponse("<html><body>swagger ui url:'/rest/docs.json'</body></html>")


@app.get("/rest/v1/public/university-profile")
async def uni_profile():
    return {"success": True, "data": {"name": "Namuna davlat universiteti", "code": "999", "logo": "",
                                      "soato": {"name": "Toshkent shahri"}, "universityType": {"name": "Universitet"}}}
