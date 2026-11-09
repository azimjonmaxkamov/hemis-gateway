# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""HEMIS OpenAPI hujjatidan endpoint katalogini yaratish va so'rov yo'lini moslash."""
import json
import re
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import Endpoint

# Har doim ruxsat etiladigan texnik parametrlar
ALWAYS_ALLOWED_PARAMS = {"l"}

# Ma'lumot doirasi (scope) kalitlari — mijozning "doira"si shu parametrlarga majburan qo'llanadi
SCOPE_KEYS = {
    "department": "Fakultet",
    "group": "Guruh",
    "specialty": "Mutaxassislik",
    "curriculum": "O'quv reja",
    "education_type": "Ta'lim turi",
    "education_form": "Ta'lim shakli",
    "level": "Kurs",
    "payment_form": "To'lov shakli",
}

_PARAM_SCOPE = {
    "_department": "department", "faculty_id": "department", "_faculty": "department",
    "_group": "group", "group_id": "group",
    "_specialty": "specialty", "_specialty_id": "specialty",
    "_curriculum": "curriculum",
    "_education_type": "education_type",
    "_education_form": "education_form",
    "_level": "level",
    "_payment_form": "payment_form",
}

PERSONAL_FIELDS = [
    "passport_pin", "passport_number", "pinfl", "phone", "person_phone", "parent_phone", "telephone",
    "email", "address", "current_address", "home_address", "mailing_address", "birth_date",
    "student_birthday", "face_image", "image", "image_full",
    # haqiqiy HEMIS javoblarida uchraydigan qo'shimcha nozik maydonlar
    "povertyLevel", "socialCategory", "currentProvince", "currentDistrict", "currentTerrain", "terrain", "district",
    "roommate_count", "hash", "hash2", "validateUrl", "contract_number", "decree_number", "pnfl", "student_pnfl",
    "employee_id_number",
]

_HIGH_RISK = re.compile(r"download|system-log|transcript|student-info|validate-phone|student-creator|"
                        r"academic-data|bim-|sso|contract|meta-log|privileged|password|ministry", re.I)
_LOW_RISK = re.compile(r"stats?\b|stat-|-count|classifier|marking-system|rating-grade|grade-type|lesson-pair|"
                       r"semester-list|version-info|department-list|specialty-list|auditorium|public", re.I)
_CACHE_LONG = re.compile(r"classifier|marking-system|rating-grade|grade-type|lesson-pair|department-list|"
                         r"specialty-list|auditorium-list|version-info|university-list|university-profile|"
                         r"semester-list|subject-meta|all-subject", re.I)
_CACHE_STATS = re.compile(r"stats?\b|stat-|-count|daily-absence", re.I)


def classify(path: str, tag: str) -> tuple[str, str]:
    """(upstream, auth_mode)"""
    t = tag.lower()
    if t.startswith("5."):
        return "fast", "fast"
    if t.startswith("2.") or path.startswith("/v1/public") or path.startswith("/public/"):
        return "hemis", "public"
    if t.startswith("1.") or (path.startswith("/v1/data/") and not t.startswith("3.")):
        return "hemis", "admin"
    return "hemis", "passthrough"


def risk_of(path: str, auth_mode: str) -> str:
    if auth_mode == "public":
        return "low"
    if _HIGH_RISK.search(path):
        return "high"
    if _LOW_RISK.search(path):
        return "low"
    return "medium"


def default_ttl(path: str, method: str, auth_mode: str) -> int:
    if method != "GET" or auth_mode in ("passthrough", "fast"):
        return 0
    if _CACHE_LONG.search(path):
        return 3600
    if _CACHE_STATS.search(path):
        return 300
    return 60 if auth_mode == "admin" else 0


def _resolve(spec: dict, obj: dict) -> dict:
    ref = obj.get("$ref")
    if not ref:
        return obj
    cur = spec
    for part in ref.lstrip("#/").split("/"):
        cur = cur.get(part, {})
    return cur


def parse_openapi(spec: dict) -> list[dict]:
    out = []
    for path, item in spec.get("paths", {}).items():
        common = item.get("parameters", [])
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            tag = (op.get("tags") or ["Boshqa"])[0]
            upstream, auth_mode = classify(path, tag)
            raw = [_resolve(spec, p) for p in common + op.get("parameters", [])]
            names = {p.get("name") for p in raw}
            params = []
            for p in raw:
                if p.get("in") not in ("query", "path"):
                    continue
                if p.get("name") == "token" and auth_mode == "fast":
                    continue  # Fast API tokenini gateway o'zi qo'shadi
                sk = _PARAM_SCOPE.get(p["name"])
                if p["name"] == "_department" and "_faculty" in names:
                    sk = None  # bu yerda _department = kafedra; qo'lda sozlanadi
                params.append({
                    "name": p["name"], "in": p.get("in"), "required": bool(p.get("required")),
                    "description": (p.get("description") or "")[:300], "scope_key": sk,
                })
            m = method.upper()
            out.append({
                "method": m, "path": path, "upstream": upstream, "group": tag,
                "summary": (op.get("summary") or "")[:500], "description": (op.get("description") or "")[:4000],
                "auth_mode": auth_mode, "params": params, "has_body": "requestBody" in op,
                "risk": risk_of(path, auth_mode), "cache_ttl": default_ttl(path, m, auth_mode),
            })
    return out


async def sync_catalog(db: AsyncSession, spec: dict | None = None, overwrite_settings: bool = False) -> dict:
    """Katalogni bazaga yozadi. Mavjud endpointlarning admin sozlamalari (auth_mode, ttl, enabled)
    saqlanadi, faqat hujjat ma'lumotlari yangilanadi."""
    if spec is None:
        p = Path(settings.OPENAPI_PATH)
        if not p.exists():
            return {"added": 0, "updated": 0, "total": 0, "skipped": "HEMIS hujjati hali sinxronlanmagan"}
        spec = json.loads(p.read_text(encoding="utf-8"))
    items = parse_openapi(spec)
    existing = {(e.method, e.path): e for e in (await db.execute(select(Endpoint))).scalars()}
    added = updated = 0
    for it in items:
        e = existing.get((it["method"], it["path"]))
        if e is None:
            db.add(Endpoint(**it))
            added += 1
        else:
            old_sk = {p["name"]: p.get("scope_key") for p in (e.params or [])}
            for p in it["params"]:
                if p["name"] in old_sk and not overwrite_settings:
                    p["scope_key"] = old_sk[p["name"]]
            e.group, e.summary, e.description = it["group"], it["summary"], it["description"]
            e.params, e.has_body = it["params"], it["has_body"]
            if overwrite_settings:
                e.auth_mode, e.upstream, e.risk, e.cache_ttl = it["auth_mode"], it["upstream"], it["risk"], it["cache_ttl"]
            updated += 1
    await db.commit()
    return {"added": added, "updated": updated, "total": len(items)}


# ---------------- yo'l moslash ----------------

class Router:
    """So'rov yo'lini katalogdagi shablonga moslaydi (masalan /v1/x/{id})."""

    def __init__(self):
        self.exact: dict[tuple[str, str, str], int] = {}
        self.patterns: list[tuple[str, str, re.Pattern, int]] = []

    def build(self, endpoints: list[Endpoint]):
        exact, patterns = {}, []
        for e in endpoints:
            if "{" in e.path:
                rx, pos = "^", 0
                for mm in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", e.path):
                    rx += re.escape(e.path[pos:mm.start()]) + f"(?P<{mm.group(1)}>[A-Za-z0-9_\\-]+)"
                    pos = mm.end()
                rx += re.escape(e.path[pos:]) + "$"
                patterns.append((e.upstream, e.method, re.compile(rx), e.id))
            else:
                exact[(e.upstream, e.method, e.path)] = e.id
        self.exact, self.patterns = exact, patterns

    def match(self, upstream: str, method: str, path: str) -> tuple[int | None, dict]:
        eid = self.exact.get((upstream, method, path))
        if eid is not None:
            return eid, {}
        for up, m, rx, eid in self.patterns:
            if up == upstream and m == method:
                mm = rx.match(path)
                if mm:
                    return eid, mm.groupdict()
        return None, {}
