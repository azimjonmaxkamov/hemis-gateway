# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

## Reporting a vulnerability

**Please do not open public issues for security problems.**

Report vulnerabilities privately to **Azimjon Makhkamov** — [raqamlivodiy@gmail.com](mailto:raqamlivodiy@gmail.com)
— or via GitHub *Security → Report a vulnerability* (private advisory). Include steps to reproduce, affected
version and impact. You will receive an acknowledgement within 72 hours; fixes are released as soon as possible
and credited to the reporter unless anonymity is requested.

## Deployment hardening checklist

- Never commit `.env`, HEMIS tokens or API keys to git. Rotate any token that was ever exposed.
- Give the HEMIS **API User** role to a dedicated HEMIS account used only by the gateway.
- Run behind TLS (see `deploy/nginx-hemis-api.conf`), restrict `/admin` with `ADMIN_ALLOWED_IPS`, enable 2FA for every admin.
- Grant each external system its own client with the minimum endpoints and filters; review high-risk endpoints.
- Configure Telegram alerts and fail2ban; rotate client keys periodically.
