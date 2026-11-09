# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Boshqaruv paneli uchun HEMIS statistikasi (faqat oldindan belgilangan, agregat hisobotlar)."""
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Request

from .admin_auth import can_view
from .kv import kv
from .models import Admin
from .state import state
from .upstream import UpstreamBusy, hemis_admin_get

router = APIRouter(prefix="/api/admin/stats", tags=["Statistika"])

GB_STUDENT = ["education_form", "education_type", "payment_form", "level", "gender", "department"]

# nomi: (HEMIS yo'li, majburiy parametrlar, foydalanuvchi o'zgartira oladigan parametrlar, kesh soniya)
REPORTS = {
    "students": ("/v1/data/student-stats", {}, {"group_by": GB_STUDENT, "_department": None, "_education_type": None,
                                                "_education_form": None, "_level": None, "_payment_form": None}, 600),
    "employees": ("/v1/data/employee-stats", {}, {"group_by": ["employee_type", "department", "position", "gender"],
                                                  "_department": None}, 600),
    "debtors": ("/v1/data/student-debtor-count", {}, {"education_year": None, "faculty_id": None}, 600),
    "debt_stats": ("/v1/data/student-debt-stats", {"list": "0"}, {"type": ["1", "2"], "group_by": GB_STUDENT,
                                                                   "min_hours": None, "_department": None}, 600),
    "attendance": ("/v1/data/attendance-stat", {"limit": "200"}, {"group_by": ["department", "university", "group"],
                                                                   "date_from": None, "date_to": None,
                                                                   "_department": None}, 300),
    "daily_absence": ("/v1/data/daily-absence", {"list": "0"}, {"date": None, "_department": None}, 300),
    "public_students": ("/v1/public/stat-student", {}, {}, 1800),
    "public_employees": ("/v1/public/stat-employee", {}, {}, 1800),
    "public_structure": ("/v1/public/stat-structure", {}, {}, 1800),
    "departments": ("/v1/data/department-list", {"limit": "200"}, {"_structure_type": None}, 3600),
    "mobility": ("/v1/data/academic-mobility-abroad-stats", {}, {"_education_year": None}, 1800),
    "shift": ("/v1/data/student-count-by-shift", {}, {}, 1800),
}


@router.get("/reports")
async def reports(a: Admin = Depends(can_view)):
    return {k: {"path": v[0], "params": {p: o for p, o in v[2].items()}} for k, v in REPORTS.items()}


@router.get("/{name}")
async def report(name: str, request: Request, a: Admin = Depends(can_view), refresh: bool = False):
    if name not in REPORTS:
        raise HTTPException(404, "Hisobot topilmadi")
    path, fixed, user, ttl = REPORTS[name]
    params = dict(fixed)
    for k, v in request.query_params.items():
        if k in ("refresh",) or not v:
            continue
        if k not in user:
            raise HTTPException(400, f"Parametr ruxsat etilmagan: {k}")
        opts = user[k]
        if opts is not None and v not in opts:
            raise HTTPException(400, f"{k} qiymati noto'g'ri")
        if len(v) > 64:
            raise HTTPException(400, "Qiymat juda uzun")
        params[k] = v
    await state.ensure_fresh()
    ck = "stats:" + hashlib.sha256(json.dumps([name, sorted(params.items())]).encode()).hexdigest()
    if not refresh:
        c = await kv.get(ck)
        if c:
            return {"cached": True, "params": params, "result": json.loads(c)}
    if not state.hemis_token and not path.startswith("/v1/public"):
        raise HTTPException(503, "HEMIS tokeni sozlanmagan (Sozlamalar bo'limi)")
    try:
        r = await hemis_admin_get(path, params)
    except UpstreamBusy:
        raise HTTPException(503, "HEMIS band, birozdan so'ng urining")
    except Exception:  # noqa: BLE001
        raise HTTPException(502, "HEMIS bilan aloqa xatosi")
    try:
        data = r.json()
    except ValueError:
        raise HTTPException(502, f"HEMIS noto'g'ri javob qaytardi ({r.status_code})")
    if r.status_code != 200:
        msg = data.get("error") or data.get("message") if isinstance(data, dict) else None
        raise HTTPException(502, f"HEMIS xatosi ({r.status_code})" + (f": {str(msg)[:200]}" if msg else ""))
    await kv.set(ck, json.dumps(data, ensure_ascii=False), ex=ttl)
    return {"cached": False, "params": params, "result": data}
