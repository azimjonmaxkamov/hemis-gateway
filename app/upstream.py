# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""HEMIS ga so'rov yuboruvchi umumiy HTTP mijoz."""
import httpx

from .config import settings
from .kv import upstream_slot
from .state import state

_client: httpx.AsyncClient | None = None


def http() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.HEMIS_TIMEOUT, connect=10),
            verify=settings.HEMIS_VERIFY_TLS,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,
            headers={"User-Agent": "HEMIS-Gateway/1.0"},
        )
    return _client


async def close():
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


class UpstreamBusy(Exception):
    pass


async def hemis_admin_get(path: str, params: dict | None = None) -> httpx.Response:
    """Ichki statistika sahifalari uchun: admin token bilan HEMIS ga GET."""
    if not await upstream_slot(settings.HEMIS_MAX_RPS):
        raise UpstreamBusy()
    return await http().get(
        state.hemis_base + path, params=params or {},
        headers={"Authorization": f"Bearer {state.hemis_token}", "Accept": "application/json"},
    )
