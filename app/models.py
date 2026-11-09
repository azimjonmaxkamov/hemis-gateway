# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
from datetime import datetime, timezone

from sqlalchemy import (JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer,
                        String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def now():
    return datetime.now(timezone.utc)


class Admin(Base):
    __tablename__ = "admins"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default="admin")  # superadmin | admin | auditor
    totp_secret: Mapped[str | None] = mapped_column(String(256), nullable=True)  # shifrlangan
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)  # sessiyalarni bekor qilish uchun
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Client(Base):
    """Gateway orqali HEMIS ga ulanadigan tashqi tizim."""
    __tablename__ = "clients"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    contact: Mapped[str] = mapped_column(String(256), default="")
    key_prefix: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    allowed_ips: Mapped[list] = mapped_column(JSON, default=list)       # ["1.2.3.4", "10.0.0.0/24"]
    allowed_origins: Mapped[list] = mapped_column(JSON, default=list)   # CORS (brauzer ilovalar uchun)
    rate_per_second: Mapped[int] = mapped_column(Integer, default=10)  # HEMIS dagi kabi soniyalik limit
    rate_per_minute: Mapped[int] = mapped_column(Integer, default=60)
    daily_quota: Mapped[int] = mapped_column(Integer, default=10000)   # 0 = cheksiz
    # Ma'lumot doirasi: {"department": [7, 9], "group": [45]} — barcha endpointlarga majburiy qo'llanadi
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    strict_scope: Mapped[bool] = mapped_column(Boolean, default=True)  # doira bilan cheklab bo'lmaydigan endpointlarni bloklash
    allow_personal_data: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    key_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Swagger hujjatlariga (/docs) kirish uchun login/parol
    docs_username: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    docs_password_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    docs_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    docs_token_version: Mapped[int] = mapped_column(Integer, default=0)
    docs_last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Kalit o'g'irlanishi gumon qilinganda vaqtincha to'xtatish
    suspended_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suspend_reason: Mapped[str] = mapped_column(String(256), default="")
    max_distinct_ips: Mapped[int | None] = mapped_column(Integer, nullable=True)  # null = global sozlama

    permissions: Mapped[list["Permission"]] = relationship(back_populates="client", cascade="all, delete-orphan")


class Endpoint(Base):
    """OpenAPI hujjatidan import qilingan HEMIS endpointi."""
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("method", "path", name="uq_endpoint"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(String(255), index=True)
    upstream: Mapped[str] = mapped_column(String(16), default="hemis")  # hemis | fast
    group: Mapped[str] = mapped_column(String(128), default="")
    summary: Mapped[str] = mapped_column(String(512), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    # admin = server HEMIS admin tokenini qo'shadi; passthrough = mijozning o'z tokeni (talaba/tutor);
    # public = token yo'q; fast = Fast API token query parametri
    auth_mode: Mapped[str] = mapped_column(String(16), default="admin")
    params: Mapped[list] = mapped_column(JSON, default=list)  # [{name,in,description,required,scope_key}]
    has_body: Mapped[bool] = mapped_column(Boolean, default=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)  # global o'chirish
    risk: Mapped[str] = mapped_column(String(8), default="low")  # low | medium | high
    cache_ttl: Mapped[int] = mapped_column(Integer, default=0)       # soniya, 0 = keshlanmaydi
    in_spec: Mapped[bool] = mapped_column(Boolean, default=True)     # joriy docs.json da bormi
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Permission(Base):
    """Mijozga berilgan endpoint ruxsati va filtr sozlamalari."""
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("client_id", "endpoint_id", name="uq_perm"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), index=True)
    # Ruxsat berilgan filtrlar ro'yxati. null = hujjatdagi barcha filtrlar
    allowed_params: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Qulflangan filtrlar: {"_department": ["7"], "_education_year": ["2024"]}
    # mijoz faqat shu qiymatlarni yubora oladi; bitta qiymat bo'lsa avtomatik qo'yiladi
    locked_params: Mapped[dict] = mapped_column(JSON, default=dict)
    max_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hidden_fields: Mapped[list] = mapped_column(JSON, default=list)  # qo'shimcha yashiriladigan maydonlar
    allow_personal: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    client: Mapped[Client] = relationship(back_populates="permissions")
    endpoint: Mapped[Endpoint] = relationship()


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class RequestLog(Base):
    __tablename__ = "request_logs"
    __table_args__ = (Index("ix_log_ts_client", "ts", "client_id"),)
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    client_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    client_name: Mapped[str] = mapped_column(String(128), default="")
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(String(255))
    endpoint_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    query: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[int] = mapped_column(Integer, index=True)
    upstream_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(256), default="")
    cache_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    denied_reason: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")


class AdminAudit(Base):
    __tablename__ = "admin_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    admin: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(256), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")


class IpRule(Base):
    """IP qora/oq ro'yxati. action=block — bloklash; allow — ishonchli (avtomatik ban qilinmaydi, bloklardan ustun)."""
    __tablename__ = "ip_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(8), default="block")      # block | allow
    area: Mapped[str] = mapped_column(String(16), default="all")         # all | gateway | admin | docs
    reason: Mapped[str] = mapped_column(String(256), default="")
    auto: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(8), default="info")   # info | warn | high
    ip: Mapped[str] = mapped_column(String(64), default="")
    client_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
