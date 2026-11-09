# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-11-09

First public release. Author: Azimjon Makhkamov.

### Added
- Filtered HEMIS API gateway: endpoint / filter / locked-value / data-scope permissions, personal-data masking.
- Admin-token injection, student/tutor token pass-through, Fast API support, caching, HEMIS rate protection.
- Admin panel: monitoring, statistics, clients, permission editor, request simulator, endpoint catalogue, logs, audit.
- **Save & synchronise** in Settings: one click checks the token, fetches the university name/logo, downloads the
  HEMIS API description (password-protected HEMIS docs supported) and builds the endpoint catalogue.
- Per-client Swagger documentation (`/docs`): API-key bar with one-click authorisation, step-by-step guide in Uzbek,
  code samples (cURL, Python, JavaScript, PHP), error-code reference; "Try it out" enabled by default.
- Security: 2FA, roles, IP allow/block lists with Excel import/export, auto-ban, stolen-key detection, CAPTCHA,
  Telegram alerts, fail2ban integration.
- Automatic HEMIS OpenAPI synchronisation with diff, impact analysis, rule adaptation, version archive and rollback.
- Multi-university: the repository ships with no institution-specific data; each institution configures its own
  HEMIS address and token, and the endpoint catalogue is downloaded from that institution's own HEMIS.
