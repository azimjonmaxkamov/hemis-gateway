# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Ruxsat dvigateli: endpoint, filtr (query parametr), doira (scope) va javob maydonlarini nazorat qiladi.

Asosiy qoidalar (barchasi "default deny"):
  1. Mijozga yoqilmagan endpoint -> 403
  2. Hujjatda yo'q parametr -> 403 (masalan `_department[]`, yashirin filtrlar)
  3. Mijozga ruxsat berilmagan filtr -> 403
  4. Bir parametrni ikki marta yuborish (parameter pollution) -> 403
  5. Qulflangan filtr: faqat ruxsat etilgan qiymatlar; bitta qiymat bo'lsa gateway o'zi qo'yadi
  6. Doira (scope): mijoz doirasi (masalan fakultet=7) har bir mos parametrga majburan qo'llanadi;
     endpointni doira bilan cheklab bo'lmasa va strict_scope yoqilgan bo'lsa -> 403
  7. limit -> max_limit dan oshsa qisqartiriladi
  8. Javobdagi shaxsiy ma'lumotlar (PINFL, pasport, telefon...) ruxsat bo'lmasa olib tashlanadi
"""
from dataclasses import dataclass, field

from .catalog import ALWAYS_ALLOWED_PARAMS, PERSONAL_FIELDS

MAX_VALUE_LEN = 256


@dataclass
class Decision:
    ok: bool
    code: str = ""
    message: str = ""
    query: list[tuple[str, str]] = field(default_factory=list)
    hidden_fields: list[str] = field(default_factory=list)


def deny(code: str, message: str) -> Decision:
    return Decision(False, code, message)


def _s(v) -> str:
    return str(v).strip()


def evaluate(endpoint, perm, client, query: list[tuple[str, str]], path_params: dict | None = None) -> Decision:
    """endpoint/perm/client — ORM obyektlar yoki shu atributli obyektlar."""
    path_params = path_params or {}
    if perm is None:
        return deny("endpoint_not_allowed", "Bu endpoint sizga ruxsat etilmagan")

    eparams = [p for p in (endpoint.params or []) if p.get("in") == "query"]
    documented = {p["name"] for p in eparams} | ALWAYS_ALLOWED_PARAMS
    locked: dict[str, list[str]] = {k: [_s(x) for x in (v or [])] for k, v in (perm.locked_params or {}).items()}
    scope: dict[str, list[str]] = {k: [_s(x) for x in v] for k, v in (client.scope or {}).items() if v}

    scope_params: dict[str, list[str]] = {}
    for p in eparams:
        if p.get("scope_key"):
            scope_params.setdefault(p["scope_key"], []).append(p["name"])
    scope_param_names = {n for names in scope_params.values() for n in names}

    if perm.allowed_params is None:
        allowed = set(documented)
    else:
        allowed = (set(perm.allowed_params) & documented) | ALWAYS_ALLOWED_PARAMS
    allowed |= set(locked) | (scope_param_names if scope else set())

    # --- 1. kelgan parametrlarni tekshirish ---
    seen: dict[str, str] = {}
    for k, v in query:
        if k in seen:
            return deny("duplicate_param", f"'{k}' parametri bir necha marta yuborilgan")
        if k not in documented:
            return deny("unknown_param", f"'{k}' parametri ushbu endpoint uchun mavjud emas")
        if k not in allowed:
            return deny("param_not_allowed", f"'{k}' filtridan foydalanish sizga ruxsat etilmagan")
        if len(v) > MAX_VALUE_LEN or any(ord(c) < 32 for c in v):
            return deny("bad_value", f"'{k}' qiymati noto'g'ri")
        seen[k] = v

    # --- 2. qulflangan filtrlar ---
    for name, values in locked.items():
        if not values:
            continue
        if name in path_params:
            if _s(path_params[name]) not in values:
                return deny("locked_value", f"'{name}' qiymatiga ruxsat yo'q")
            continue
        if name not in documented:
            if any(p.get("name") == name and p.get("in") == "path" for p in (endpoint.params or [])):
                continue
            # Qulf qo'yilgan filtr yangi hujjatda yo'q — filtrsiz (kengroq) ma'lumot bermaslik uchun rad etamiz
            return deny("locked_param_missing",
                        f"Qulflangan '{name}' filtri endi mavjud emas. Administrator ruxsatni yangilashi kerak")
        if name in seen:
            if _s(seen[name]) not in values:
                return deny("locked_value", f"'{name}' uchun faqat ruxsat etilgan qiymatlar: {', '.join(values)}")
        elif len(values) == 1:
            seen[name] = values[0]
        else:
            return deny("locked_required", f"'{name}' parametrini ko'rsatish majburiy: {', '.join(values)}")

    # --- 3. doira (scope) ---
    if scope and endpoint.auth_mode in ("admin", "fast"):  # server tokeni bilan ishlaydigan rejimlar
        for key, values in scope.items():
            names = scope_params.get(key, [])
            if not names:
                if getattr(client, "strict_scope", True):
                    return deny("scope_unenforceable",
                                f"Bu endpointni sizning doirangiz ({key}) bo'yicha cheklab bo'lmaydi")
                continue
            for n in names:
                if n in seen and _s(seen[n]) not in values:
                    return deny("scope_violation", f"'{n}'={seen[n]} sizning doirangizdan tashqarida")
            primary = names[0]
            if not any(n in seen for n in names):
                if len(values) == 1:
                    seen[primary] = values[0]
                else:
                    return deny("scope_required",
                                f"'{primary}' parametrini ko'rsating (ruxsat: {', '.join(values)})")

    # --- 4. limit ---
    if perm.max_limit and "limit" in documented:
        try:
            lim = int(seen.get("limit", 20))
        except ValueError:
            return deny("bad_value", "'limit' butun son bo'lishi kerak")
        seen["limit"] = str(max(1, min(lim, perm.max_limit)))

    # --- 5. yashiriladigan maydonlar ---
    # Shaxsiy ma'lumot faqat mijoz darajasida HAM, endpoint darajasida HAM ruxsat bo'lsa ko'rinadi
    hidden = list(perm.hidden_fields or [])
    if not (perm.allow_personal and getattr(client, "allow_personal_data", False)):
        hidden += PERSONAL_FIELDS

    return Decision(True, query=list(seen.items()), hidden_fields=sorted(set(hidden)))


# ---------------- javobni filtrlash ----------------

def mask(obj, hidden: list[str]):
    """Kalit nomi bo'yicha (istalgan chuqurlikda) yoki nuqtali yo'l bo'yicha ("data.items.name") maydonlarni olib tashlaydi."""
    if not hidden:
        return obj
    names = {h for h in hidden if "." not in h}
    paths = [h.split(".") for h in hidden if "." in h]

    def by_name(o):
        if isinstance(o, dict):
            return {k: by_name(v) for k, v in o.items() if k not in names}
        if isinstance(o, list):
            return [by_name(x) for x in o]
        return o

    def drop_path(o, parts):
        if isinstance(o, list):
            for x in o:
                drop_path(x, parts)
            return
        if not isinstance(o, dict) or not parts:
            return
        head, rest = parts[0], parts[1:]
        keys = list(o.keys()) if head == "*" else [head]
        for k in keys:
            if k not in o:
                continue
            if not rest:
                o.pop(k, None)
            else:
                drop_path(o[k], rest)

    out = by_name(obj) if names else obj
    for p in paths:
        drop_path(out, p)
    return out
