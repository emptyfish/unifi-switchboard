# UniFi Switchboard

Lightweight web UI to enable and disable UniFi zone-based firewall policies from any browser on your LAN.

![Python](https://img.shields.io/badge/python-3.12-blue) ![Flask](https://img.shields.io/badge/flask-3.0-lightgrey) ![Docker](https://img.shields.io/badge/docker-ready-blue)

---

## Overview

UniFi's web interface requires navigating several layers of menus to toggle a firewall policy. This app puts your custom rules on a single page — one tap to enable or disable.

Only user-created policies are shown. System-generated default policies are hidden.

**UI:**

- Dashboard listing all your custom firewall policies
- Toggle switch per rule with instant feedback
- Login-protected with configurable password

---

## Compatibility

| Component | Requirement |
|-----------|-------------|
| UniFi OS | 3.x+ |
| UniFi Network app | 8.x+ (firmware 10.x on UCG) |
| API | `firewall-policies` (zone-based, v2) |
| Hardware tested | UCG-Max |

This app targets the **zone-based firewall** introduced in UniFi Network 8.x. It uses the `GET/PUT /proxy/network/v2/api/site/default/firewall-policies` API. It will **not** work with the legacy traffic rules or pre-zone-based firewall setups.

---

## Quick Start

### Docker (recommended)

```bash
docker run -d \
  --name unifi-switchboard \
  --restart unless-stopped \
  -p 5055:5055 \
  -e UNIFI_URL=https://your-unifi.url \
  -e UNIFI_USERNAME=your-unifi-username \
  -e UNIFI_PASSWORD=your-unifi-password \
  -e APP_PASSWORD=your-app-password \
  -e SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
  ghcr.io/YOUR_USER/unifi-switchboard:latest
```

Then open `http://YOUR_HOST:5055`.

### Docker Compose

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```env
UNIFI_URL=https://your-unifi.url
UNIFI_USERNAME=your-unifi-username
UNIFI_PASSWORD=your-unifi-password
APP_PASSWORD=your-app-password
SECRET_KEY=  # generate: python3 -c "import secrets; print(secrets.token_hex(32))"
```

Then start:

```bash
docker compose up -d
```

---

## Configuration

All configuration is via environment variables — no config files.

| Variable | Required | Description |
|----------|----------|-------------|
| `UNIFI_URL` | Yes | Base URL of your UniFi controller, e.g. `https://192.168.1.1` |
| `UNIFI_USERNAME` | Yes | UniFi admin username |
| `UNIFI_PASSWORD` | Yes | UniFi admin password (min 8 chars) |
| `APP_PASSWORD` | Yes | Password to log into this web UI (min 8 chars) |
| `SECRET_KEY` | Yes | Random string for session encryption (min 32 chars) |
| `UNIFI_SITE` | No | UniFi site name (default: `default`). Change if you use multiple sites or a custom site name |
| `UNIFI_API_KEY` | No | Local UniFi API key — enables correct rule evaluation order. Generate in Network → Settings → API Keys |
| `TRUST_PROXY` | No | Set `true` when running behind Cloudflare Tunnel or a reverse proxy — enables `ProxyFix` and the `Secure` cookie flag |

---

## Unraid

Import `unraid.xml` as a custom template in the Docker tab, or configure a new container manually:

- **Repository:** `ghcr.io/emptyfish/unifi-switchboard:latest`
- **Port:** `5055`
- **Environment variables:** as above — no volume mounts needed

---

## Remote Access

To access from outside your LAN without opening ports, route through a Cloudflare Tunnel:

```yaml
ingress:
  - hostname: switchboard.yourdomain.com
    service: http://localhost:5055
  - service: http_status:404
```

When behind HTTPS (Cloudflare or otherwise), set `TRUST_PROXY=true` in your environment.

---

## Security

- Passwords compared with `hmac.compare_digest` (timing-safe)
- Rate limiting: 10 login attempts/min, 60 rule fetches/min, 30 toggles/min
- Security headers: `X-Frame-Options`, `X-Content-Type-Options`, `CSP`, `Referrer-Policy`, `Permissions-Policy`
- Sessions: `HttpOnly`, `SameSite=Strict`, expires on browser close
- All credentials are environment variables — nothing written to disk
- Container runs as non-root (`uid 1000`)
- Served by Gunicorn in production

> **Note:** SSL verification is disabled when connecting to the UniFi controller since it uses a self-signed certificate by default. Traffic stays on your local network.

---

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in your values
bash run.sh
```

App runs at `http://localhost:5055`.

---

## Logs

```bash
docker logs unifi-switchboard -f
```
