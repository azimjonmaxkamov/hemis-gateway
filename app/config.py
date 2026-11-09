# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Tizim sozlamalari (.env orqali)."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- umumiy ---
    APP_NAME: str = "HEMIS API Gateway"
    PUBLIC_BASE_URL: str = ""          # masalan https://hemis-api.otm.uz (bo'sh = so'rov manzilidan aniqlanadi)
    ENV: str = "production"  # production | development

    # --- maxfiy kalitlar (MAJBURIY: production uchun o'zgartiring) ---
    SECRET_KEY: str = "change-me-please-very-long-random-string"   # admin JWT imzosi
    ENCRYPTION_KEY: str = ""        # Fernet kaliti (HEMIS tokenlarini DB da shifrlash uchun)
    API_KEY_PEPPER: str = "change-me-pepper"                        # mijoz kalitlari HMAC "qalampiri"

    # --- ma'lumotlar bazasi / redis ---
    DATABASE_URL: str = "postgresql+asyncpg://gateway:gateway@db:5432/gateway"
    REDIS_URL: str = ""             # bo'sh bo'lsa xotira ichidagi zaxira ishlatiladi (faqat bitta worker!)

    # --- HEMIS upstream ---
    HEMIS_BASE_URL: str = ""           # masalan https://student.otm.uz/rest (panel orqali ham kiritiladi)
    HEMIS_ADMIN_TOKEN: str = ""     # Backend API tokeni (panel orqali ham o'rnatish mumkin)
    HEMIS_FAST_API_URL: str = ""    # Fast API server manzili (agar bo'lsa)
    HEMIS_FAST_API_TOKEN: str = ""
    HEMIS_TIMEOUT: float = 30.0
    HEMIS_MAX_RPS: int = 9          # HEMIS Backend API limiti 10 rps — biz 9 dan oshirmaymiz
    HEMIS_VERIFY_TLS: bool = True

    # --- admin panel xavfsizligi ---
    ADMIN_ALLOWED_IPS: str = ""     # vergul bilan: "10.0.0.0/8,195.158.1.2" ; bo'sh = hamma
    ADMIN_SESSION_HOURS: int = 8
    ADMIN_LOGIN_MAX_FAILS: int = 5
    ADMIN_LOGIN_LOCK_MINUTES: int = 15
    TRUST_PROXY_HEADERS: bool = True  # nginx ortida bo'lsa X-Forwarded-For ishonchli

    # --- log ---
    LOG_RETENTION_DAYS: int = 180
    LOG_BODY_MAX: int = 0           # javob tanasini logga yozish (0 = yozilmaydi)

    # --- dastlabki superadmin (birinchi ishga tushishda) ---
    INIT_ADMIN_USERNAME: str = "admin"
    INIT_ADMIN_PASSWORD: str = ""

    OPENAPI_PATH: str = "data/hemis-openapi.json"
    SECURITY_LOG: str = "data/security.log"   # fail2ban shu faylni kuzatadi


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
