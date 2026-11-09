# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Oq ro'yxat (allow) va qora ro'yxat (block): Excel eksport, shablon, import, ommaviy o'chirish."""
import io
import ipaddress
import re
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import guard
from .admin_auth import audit, can_edit, can_view
from .db import get_db
from .kv import kv
from .models import Admin, IpRule
from .security import client_ip
from .state import bump_version

router = APIRouter(prefix="/api/admin/security/lists", tags=["IP ro'yxatlar"])

TZ = timezone(timedelta(hours=5))  # Asia/Tashkent (Excelda vaqtlar mahalliy vaqtda)
MAX_ROWS = 5000
KIND_L = {"allow": "Oq ro'yxat (ishonchli IP)", "block": "Qora ro'yxat (bloklangan IP)"}
AREA_OUT = {"all": "hammasi", "gateway": "gateway", "admin": "admin", "docs": "docs"}
AREA_IN = {"": "all", "hammasi": "all", "barchasi": "all", "all": "all", "hammasiga": "all",
           "gateway": "gateway", "api": "gateway", "gateway (api)": "gateway",
           "admin": "admin", "admin panel": "admin", "panel": "admin", "docs": "docs", "hujjatlar": "docs"}
HEAD = ["IP / tarmoq", "Qayerga", "Tugash vaqti", "Sabab"]
HEAD_EXTRA = ["Turi", "Holat", "Kim qo'shgan", "Qo'shilgan vaqt"]
_REL = re.compile(r"^(\d+)\s*(daqiqa|daq|min|soat|s|kun|k|hafta|oy)$", re.I)


def _kind(kind: str) -> str:
    if kind not in KIND_L:
        raise HTTPException(404, "Ro'yxat turi: allow yoki block")
    return kind


def _local(d: datetime | None):
    if not d:
        return None
    return guard._aware(d).astimezone(TZ).replace(tzinfo=None)


def _style(ws, widths):
    hdr_fill = PatternFill("solid", fgColor="2A78D6")
    for i, w in enumerate(widths, 1):
        c = ws.cell(row=1, column=i)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = hdr_fill
        c.alignment = Alignment(vertical="center")
        ws.column_dimensions[c.column_letter].width = w
    ws.freeze_panes = "A2"
    ws.row_dimensions[1].height = 22


def _guide(wb: Workbook, kind: str):
    g = wb.create_sheet("Yo'riqnoma")
    rows = [
        [KIND_L[kind] + " — import qoidalari"], [],
        ["Ustun", "Majburiy", "Qiymatlar"],
        ["IP / tarmoq", "ha", "Bitta IP (195.158.1.10) yoki tarmoq CIDR ko'rinishida (195.158.0.0/16, 2001:db8::/32)"],
        ["Qayerga", "yo'q", "hammasi (standart) · gateway — API so'rovlari · admin — boshqaruv paneli · docs — Swagger sahifasi"],
        ["Tugash vaqti", "yo'q", "Bo'sh yoki «doimiy» — muddatsiz. Sana: 31.12.2026 yoki 31.12.2026 18:00 (Toshkent vaqti). "
                                 "Nisbiy: «30 daqiqa», «12 soat», «7 kun», «2 hafta», «3 oy»"],
        ["Sabab", "yo'q", "Ixtiyoriy izoh (256 belgigacha)"], [],
        ["Rejimlar"],
        ["Qo'shish", "", "Fayldagi IP lar qo'shiladi; mavjudlari (IP + qayerga) yangilanadi"],
        ["Almashtirish", "", "Ro'yxatdagi qo'lda kiritilgan barcha yozuvlar o'chirilib, fayldagilar bilan almashtiriladi "
                             "(avtomatik banlar saqlanadi)"], [],
        ["Eslatmalar"],
        ["", "", "Birinchi varaqdagi 1-qator sarlavha; sarlavha nomlari bo'yicha o'qiladi, ustunlar tartibi muhim emas."],
        ["", "", f"Bir faylda ko'pi bilan {MAX_ROWS} ta qator. Xato qatorlar o'tkazib yuboriladi va hisobotda ko'rsatiladi."],
        ["", "", "Eksport faylidagi qo'shimcha ustunlar (Turi, Holat, …) importda e'tiborga olinmaydi."],
    ]
    if kind == "block":
        rows.append(["", "", "Sizning joriy IP manzilingizni hammasi/admin ga bloklab bo'lmaydi; /8 dan keng tarmoqlar rad etiladi."])
    for r in rows:
        g.append(r)
    g["A1"].font = Font(bold=True, size=13)
    for cell in ("A3", "B3", "C3", "A9", "A13"):
        g[cell].font = Font(bold=True)
    g.column_dimensions["A"].width = 16
    g.column_dimensions["B"].width = 10
    g.column_dimensions["C"].width = 110


def _book(kind: str, rules: list | None) -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "Oq ro'yxat" if kind == "allow" else "Qora ro'yxat"
    extra = rules is not None
    ws.append(HEAD + (HEAD_EXTRA if extra else []))
    _style(ws, [22, 12, 20, 50] + ([12, 12, 16, 20] if extra else []))
    dv = DataValidation(type="list", formula1='"hammasi,gateway,admin,docs"', allow_blank=True)
    ws.add_data_validation(dv)
    dv.add(f"B2:B{MAX_ROWS + 1}")
    now = datetime.now(timezone.utc)
    for r in rules or []:
        active = not r.expires_at or guard._aware(r.expires_at) > now
        ws.append([r.cidr, AREA_OUT.get(r.area, r.area), _local(r.expires_at) or "doimiy", r.reason,
                   "avtomatik" if r.auto else "qo'lda", "faol" if active else "tugagan", r.created_by,
                   _local(r.created_at)])
    for row in ws.iter_rows(min_row=2):
        for c in (row[2], row[7] if len(row) > 7 else None):
            if c is not None and isinstance(c.value, datetime):
                c.number_format = "DD.MM.YYYY HH:MM"
    _guide(wb, kind)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _xlsx_response(data: bytes, name: str):
    return StreamingResponse(io.BytesIO(data), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


@router.get("/{kind}/export")
async def export(kind: str, a: Admin = Depends(can_view), db: AsyncSession = Depends(get_db),
                 include_auto: bool = True, include_expired: bool = False):
    _kind(kind)
    q = select(IpRule).where(IpRule.action == kind).order_by(IpRule.cidr)
    rules = (await db.execute(q)).scalars().all()
    now = datetime.now(timezone.utc)
    rules = [r for r in rules if (include_auto or not r.auto)
             and (include_expired or not r.expires_at or guard._aware(r.expires_at) > now)]
    fname = f"{'oq' if kind == 'allow' else 'qora'}-royxat-{datetime.now(TZ):%Y%m%d-%H%M}.xlsx"
    return _xlsx_response(_book(kind, rules), fname)


@router.get("/{kind}/template")
async def template(kind: str, a: Admin = Depends(can_view)):
    _kind(kind)
    return _xlsx_response(_book(kind, None), f"{'oq' if kind == 'allow' else 'qora'}-royxat-shablon.xlsx")


# ---------------- import ----------------

def parse_expiry(v, now: datetime) -> tuple[datetime | None, str | None]:
    """(utc datetime | None=doimiy, xato)"""
    if v is None:
        return None, None
    if isinstance(v, datetime):
        d = v.replace(tzinfo=TZ) if v.tzinfo is None else v
    elif isinstance(v, date):
        d = datetime(v.year, v.month, v.day, 23, 59, 59, tzinfo=TZ)
    else:
        s = str(v).strip().lower()
        if s in ("", "doimiy", "muddatsiz", "-", "—", "permanent", "never"):
            return None, None
        m = _REL.match(s)
        if m:
            n, u = int(m.group(1)), m.group(2)
            mult = {"daqiqa": 60, "daq": 60, "min": 60, "soat": 3600, "s": 3600, "kun": 86400, "k": 86400,
                    "hafta": 7 * 86400, "oy": 30 * 86400}[u]
            return now + timedelta(seconds=n * mult), None
        d = None
        for fmt in ("%d.%m.%Y %H:%M", "%d.%m.%Y", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y-%m-%dT%H:%M", "%d/%m/%Y"):
            try:
                d = datetime.strptime(s, fmt)
                if "%H" not in fmt:
                    d = d.replace(hour=23, minute=59, second=59)
                d = d.replace(tzinfo=TZ)
                break
            except ValueError:
                continue
        if d is None:
            return None, f"tugash vaqti tushunarsiz: «{v}»"
    d = d.astimezone(timezone.utc)
    if d <= now:
        return None, "tugash vaqti o'tib ketgan"
    return d, None


def _norm_cidr(raw) -> tuple[str | None, object, str | None]:
    s = str(raw or "").strip()
    if not s:
        return None, None, "IP bo'sh"
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None, None, f"noto'g'ri IP/CIDR: «{s}»"
    if net.prefixlen < (8 if net.version == 4 else 32):
        return None, None, "juda keng diapazon"
    return (str(net.network_address) if net.num_addresses == 1 else str(net)), net, None


def _find_cols(header: list) -> dict:
    keys = {"ip": ("ip", "ip / tarmoq", "ip/tarmoq", "tarmoq", "cidr", "ip manzil", "address"),
            "area": ("qayerga", "area", "hudud", "joy"),
            "exp": ("tugash vaqti", "tugash", "muddat", "expires", "expires_at", "amal qilish muddati"),
            "reason": ("sabab", "izoh", "reason", "comment")}
    out = {}
    for i, h in enumerate(header):
        hh = str(h or "").strip().lower()
        for k, names in keys.items():
            if k not in out and hh in names:
                out[k] = i
    return out


@router.post("/{kind}/import")
async def import_list(kind: str, request: Request, file: UploadFile = File(...), mode: str = Form("merge"),
                      dry_run: bool = Form(False), a: Admin = Depends(can_edit), db: AsyncSession = Depends(get_db)):
    _kind(kind)
    if mode not in ("merge", "replace"):
        raise HTTPException(400, "Rejim: merge yoki replace")
    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(400, "Fayl 5 MB dan katta")
    try:
        wb = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "Excel (.xlsx) faylini o'qib bo'lmadi")
    ws = wb.worksheets[0]
    rows = ws.iter_rows(values_only=True)
    header = next(rows, None) or []
    cols = _find_cols(list(header))
    if "ip" not in cols:
        raise HTTPException(400, "Birinchi qatorda «IP / tarmoq» sarlavhasi topilmadi (shablondan foydalaning)")

    now = datetime.now(timezone.utc)
    me = client_ip(request)
    try:
        my_addr = ipaddress.ip_address(me)
    except ValueError:
        my_addr = None
    allows = [] if kind == "allow" else [
        (ipaddress.ip_network(r.cidr, strict=False), r.area) for r in
        (await db.execute(select(IpRule).where(IpRule.action == "allow"))).scalars()]

    items, errors, warnings, seen = [], [], [], set()
    n = 0
    for idx, row in enumerate(rows, start=2):
        if row is None or all(v in (None, "") for v in row):
            continue
        n += 1
        if n > MAX_ROWS:
            errors.append({"row": idx, "value": "", "error": f"{MAX_ROWS} qatordan ortig'i o'qilmadi"})
            break
        g = lambda k: row[cols[k]] if k in cols and cols[k] < len(row) else None  # noqa: E731
        cidr, net, e = _norm_cidr(g("ip"))
        if e:
            errors.append({"row": idx, "value": str(g("ip") or ""), "error": e})
            continue
        area = AREA_IN.get(str(g("area") or "").strip().lower())
        if area is None:
            errors.append({"row": idx, "value": cidr, "error": f"«Qayerga» noto'g'ri: «{g('area')}»"})
            continue
        exp, e = parse_expiry(g("exp"), now)
        if e:
            errors.append({"row": idx, "value": cidr, "error": e})
            continue
        if kind == "block" and area in ("all", "admin") and my_addr and my_addr.version == net.version and my_addr in net:
            errors.append({"row": idx, "value": cidr, "error": f"sizning IP manzilingiz ({me}) — bloklab bo'lmaydi"})
            continue
        key = (cidr, area)
        if key in seen:
            warnings.append({"row": idx, "value": cidr, "error": "faylda takrorlangan — o'tkazib yuborildi"})
            continue
        seen.add(key)
        if kind == "block":
            for anet, aarea in allows:
                if anet.version == net.version and (net.subnet_of(anet)) and aarea in ("all", area):
                    warnings.append({"row": idx, "value": cidr, "error": f"oq ro'yxatdagi {anet} ichida — blok amal qilmaydi"})
                    break
        reason = str(g("reason") or "").strip()[:256] or ("import" if kind == "block" else "")
        items.append({"cidr": cidr, "area": area, "expires_at": exp, "reason": reason, "single": net.num_addresses == 1})

    existing = {(r.cidr, r.area): r for r in
                (await db.execute(select(IpRule).where(IpRule.action == kind))).scalars()}
    to_add = [i for i in items if (i["cidr"], i["area"]) not in existing]
    to_upd = [i for i in items if (i["cidr"], i["area"]) in existing]
    removed = []
    if mode == "replace":
        keys = {(i["cidr"], i["area"]) for i in items}
        removed = [r for k, r in existing.items() if not r.auto and k not in keys]
    result = {"rows": n, "added": len(to_add), "updated": len(to_upd), "removed": len(removed),
              "errors": errors[:300], "warnings": warnings[:300], "error_count": len(errors),
              "warning_count": len(warnings), "dry_run": dry_run, "mode": mode}
    if dry_run:
        return result

    for r in removed:
        await db.delete(r)
        if kind == "block":
            await kv.delete(f"ban:{r.cidr}")
    for i in to_upd:
        r = existing[(i["cidr"], i["area"])]
        r.expires_at, r.reason, r.auto, r.created_by = i["expires_at"], i["reason"] or r.reason, False, a.username
    for i in to_add:
        db.add(IpRule(cidr=i["cidr"], action=kind, area=i["area"], reason=i["reason"], auto=False,
                      expires_at=i["expires_at"], created_by=a.username))
    await audit(db, a.username, f"ip_{kind}_import", file.filename or "", {k: result[k] for k in (
        "rows", "added", "updated", "removed", "error_count", "mode")}, client_ip(request))
    await db.commit()

    for i in to_add + to_upd:
        secs = int((i["expires_at"] - now).total_seconds()) if i["expires_at"] else None
        if kind == "block":
            if i["single"] and i["area"] == "all":
                await kv.set(f"ban:{i['cidr']}", "import", ex=secs or 10 * 365 * 86400)
            guard._seclog(f"BAN ip={i['cidr']} duration={secs or 0} auto=0 reason=excel_import")
        else:
            await kv.delete(f"ban:{i['cidr']}")
    await bump_version()
    await guard.event("ip_list_import", f"{KIND_L[kind]}: Excel import ({'almashtirish' if mode == 'replace' else 'qo`shish'}) — "
                      f"+{len(to_add)} yangi, {len(to_upd)} yangilangan, {len(removed)} o'chirilgan, {len(errors)} xato. "
                      f"Admin: {a.username}", "warn" if kind == "block" else "info", alert=False)
    return result


class BulkDel(BaseModel):
    ids: list[int]


@router.post("/{kind}/bulk-delete")
async def bulk_delete(kind: str, data: BulkDel, request: Request, a: Admin = Depends(can_edit),
                      db: AsyncSession = Depends(get_db)):
    _kind(kind)
    rs = (await db.execute(select(IpRule).where(IpRule.action == kind, IpRule.id.in_(data.ids[:MAX_ROWS])))).scalars().all()
    for r in rs:
        if kind == "block":
            await kv.delete(f"ban:{r.cidr}")
            await kv.delete(f"abuse:{r.cidr}")
            guard._seclog(f"UNBAN ip={r.cidr} by={a.username}")
    await db.execute(delete(IpRule).where(IpRule.id.in_([r.id for r in rs])))
    await audit(db, a.username, f"ip_{kind}_bulk_delete", "", {"count": len(rs), "cidrs": [r.cidr for r in rs][:50]},
                client_ip(request))
    await db.commit()
    await bump_version()
    return {"ok": True, "deleted": len(rs)}
