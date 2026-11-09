# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Toza o'rnatish: HEMIS hujjati yo'q holatda `python -m app.cli init` yiqilmasligi kerak (Docker/systemd CMD)."""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _run(env_extra, *args):
    env = {**os.environ, **env_extra}
    return subprocess.run([sys.executable, "-m", "app.cli", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)


def test_cli_init_on_fresh_install_without_spec():
    tmp = tempfile.mkdtemp()
    env = {"DATABASE_URL": f"sqlite+aiosqlite:///{tmp}/fresh.db", "REDIS_URL": "", "ENV": "development",
           "SECRET_KEY": "x" * 40, "INIT_ADMIN_PASSWORD": "Admin12345pass",
           "OPENAPI_PATH": f"{tmp}/hemis-openapi.json"}         # fayl ataylab yo'q
    r = _run(env, "init")
    assert r.returncode == 0, r.stderr
    assert "katalogi bo'sh" in r.stdout
    r = _run(env, "init")                                      # qayta ishga tushirish ham xatosiz
    assert r.returncode == 0, r.stderr
