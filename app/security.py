# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Kriptografiya va xavfsizlik yordamchilari."""
import base64
import hashlib
import hmac
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pyotp
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Request

from .config import settings

# ---------------- parol ----------------

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(pw: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), h.encode())
    except ValueError:
        return False


def password_problems(pw: str) -> str | None:
    if len(pw) < 10:
        return "Parol kamida 10 belgidan iborat bo'lishi kerak"
    if not any(c.isdigit() for c in pw) or not any(c.isalpha() for c in pw):
        return "Parolda harf va raqam bo'lishi kerak"
    return None


# ---------------- mijoz API kaliti ----------------
# Format: hg_<prefix 10>_<secret 40>. Bazada faqat HMAC-SHA256 saqlanadi.

def _key_hash(full_key: str) -> str:
    return hmac.new(settings.API_KEY_PEPPER.encode(), full_key.encode(), hashlib.sha256).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    prefix = secrets.token_hex(5)
    secret = secrets.token_urlsafe(30)
    full = f"hg_{prefix}_{secret}"
    return full, prefix, _key_hash(full)


def parse_api_key(full_key: str) -> str | None:
    parts = full_key.strip().split("_", 2)
    if len(parts) != 3 or parts[0] != "hg" or len(parts[1]) != 10:
        return None
    return parts[1]


def verify_api_key(full_key: str, stored_hash: str) -> bool:
    return hmac.compare_digest(_key_hash(full_key.strip()), stored_hash)


# ---------------- shifrlash (Fernet) ----------------

def _fernet() -> Fernet:
    raw = settings.ENCRYPTION_KEY or settings.SECRET_KEY
    try:
        if settings.ENCRYPTION_KEY:
            return Fernet(settings.ENCRYPTION_KEY.encode())
    except ValueError:
        pass
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()))


def encrypt(s: str) -> str:
    return _fernet().encrypt(s.encode()).decode() if s else ""


def decrypt(s: str) -> str:
    if not s:
        return ""
    try:
        return _fernet().decrypt(s.encode()).decode()
    except InvalidToken:
        return ""


# ---------------- admin sessiya (JWT) ----------------

def create_admin_token(admin_id: int, role: str, token_version: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(admin_id), "role": role, "tv": token_version, "iat": now,
               "exp": now + timedelta(hours=settings.ADMIN_SESSION_HOURS), "typ": "admin"}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_admin_token(tok: str) -> dict | None:
    try:
        p = jwt.decode(tok, settings.SECRET_KEY, algorithms=["HS256"])
        return p if p.get("typ") == "admin" else None
    except jwt.PyJWTError:
        return None


# ---------------- 2FA ----------------

def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    return bool(secret) and pyotp.TOTP(secret).verify((code or "").strip(), valid_window=1)


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="HEMIS Gateway")


# ---------------- IP ----------------

def client_ip(request: Request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        xri = request.headers.get("x-real-ip")
        if xri:
            return xri.strip()
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def ip_allowed(ip: str, rules: list[str] | str) -> bool:
    if isinstance(rules, str):
        rules = [r.strip() for r in rules.split(",") if r.strip()]
    if not rules:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for r in rules:
        try:
            if addr in ipaddress.ip_network(r, strict=False):
                return True
        except ValueError:
            continue
    return False
