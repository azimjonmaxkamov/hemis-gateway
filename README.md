# HEMIS API Gateway

> 🇺🇿 [O'zbekcha qo'llanma](README.uz.md)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)
![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg)

**HEMIS API Gateway** is a secure, self-hosted gateway and control panel for the
**HEMIS** (Higher Education Management Information System) used by higher-education institutions in Uzbekistan.

External systems (bots, portals, mobile apps, partner services) never get the university's HEMIS admin token.
They connect to the gateway with their own key, and the gateway forwards only what each client is explicitly
allowed to see — per endpoint, per filter and per value — while logging every request.

```
External system ──(hg_ key)──▶  HEMIS API Gateway  ──(admin token, server-side only)──▶  student.<university>.uz/rest
                                │ endpoint permissions
                                │ allowed filters · locked values · data scope (faculty, group…)
                                │ rate limits · IP allow-list · CORS · key expiry
                                │ personal-data masking (PINFL, passport, phone, address…)
                                └ audit log · caching · HEMIS 10 rps protection · auto-ban
```

Each university deploys its own instance and enters its own HEMIS address and API token in the admin panel.

## Features

**Gateway**
- All HEMIS endpoints (~350: Backend, Public, Student, Tutor, Ministry, Fast API) — the catalogue is downloaded from
  **your own HEMIS** on first synchronisation. The repository ships no HEMIS documentation and no institution data.
- **Default deny**: unknown endpoints, undocumented parameters, non-permitted filters and parameter pollution are rejected.
- **Filter-level control**: allowed filters per endpoint, **locked values** (injected automatically), `max_limit`.
- **Data scope**: give a client "faculty = 7" and the gateway enforces it on every endpoint; endpoints that cannot be scoped are blocked.
- **Personal data masking** unless explicitly allowed at both client and endpoint level.
- Admin-token injection, pass-through of student/tutor JWTs, Fast API token injection.
- Per-client limits (per second / minute / day), global HEMIS throttle, Redis cache.

**Security**
- Hashed API keys, encrypted secrets, admin 2FA (TOTP), roles (superadmin / admin / auditor), CSRF, CSP, lockouts.
- IP **allow-list / block-list** with Excel import/export, progressive **auto-ban**, stolen-key detection
  (too many distinct IPs → client suspended), server-side CAPTCHA, Telegram alerts, fail2ban integration.

**Control panel** (`/admin`)
- Live monitoring, HEMIS statistics dashboards (students, staff, debtors, attendance, absences…).
- Client management with a permission editor, request simulator and per-client logs.
- Endpoint catalogue, request log, admin audit log.

**Client documentation** (`/docs`)
- Swagger UI per client, protected by a login/password issued by the admin, showing **only** the endpoints,
  filters and values that client is allowed to use, with "Try it out".

**Automatic HEMIS synchronisation**
- The gateway downloads the HEMIS OpenAPI document itself (auto-discovers the URL, supports password-protected docs),
  shows a diff with per-client impact, applies safe changes automatically, adapts permission rules, keeps a version
  archive with rollback, and asks for approval when a change could affect existing clients.

## Quick start (Docker)

```bash
git clone <this-repo> hemis-gateway && cd hemis-gateway
cp .env.example .env
docker compose run --rm app python -m app.cli gen-secrets   # paste the output into .env
sudo chown -R 10001 data
docker compose up -d --build
docker compose logs app | grep -i superadmin               # first admin password
```

Then open `https://<your-gateway>/admin`:

1. **Settings** → enter your HEMIS address (any form works, e.g. `https://student.<university>.uz/rest/docs#/`),
   the API token (HEMIS admin panel → a user with the **API User** role) and, if your HEMIS docs page asks for one,
   the docs password → **Save & synchronise**. The gateway checks the token, fetches the university name and logo,
   downloads the HEMIS API description and builds the endpoint catalogue — all in one step.
2. **Profile** → change the password and enable 2FA.
3. **Security** → add your campus network to the allow-list, configure Telegram alerts.
4. **Clients** → create a client, set its permissions, hand over the API key and the `/docs` credentials.

Reverse proxy and TLS: see [`deploy/nginx-hemis-api.conf`](deploy/nginx-hemis-api.conf); fail2ban: [`deploy/fail2ban`](deploy/fail2ban).

## Using the gateway (for client developers)

```bash
curl -H "X-Gateway-Key: hg_xxxxxxxxxx_xxxx" \
  "https://<gateway>/rest/v1/data/student-list?limit=50&_group=45"
```

Paths are identical to HEMIS. Errors use the HEMIS format plus a `gateway_code`:
`{"success": false, "error": "...", "code": 403, "gateway_code": "param_not_allowed"}`.

## Development

```bash
pip install -r requirements.txt pytest pytest-asyncio
pytest -q tests
```

Stack: Python 3.12 · FastAPI · SQLAlchemy (PostgreSQL / SQLite) · Redis · vanilla JS (no build step) · Swagger UI.

## Contributing & security

- Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
- Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Author and license

**HEMIS API Gateway** is created and maintained by **Azimjon Makhkamov** ([raqamlivodiy@gmail.com](mailto:raqamlivodiy@gmail.com)).

Copyright © 2026 Azimjon Makhkamov. Licensed under the [Apache License, Version 2.0](LICENSE).
You may use, modify and distribute this software free of charge, provided that the [LICENSE](LICENSE) and
[NOTICE](NOTICE) files and the copyright/attribution notices are retained and modified files are marked as changed.

"HEMIS" and the HEMIS API belong to their respective owners. This is an independent project based on the
official HEMIS API documentation and is not endorsed by the HEMIS developers.
If you use this project in research or publications, please cite it (see [CITATION.cff](CITATION.cff)).
