import os
import hmac
import logging
import re
from urllib.parse import urlparse

import requests
import urllib3
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def _require_env(key, min_length=1):
    val = os.environ.get(key, "").strip()
    if not val:
        raise RuntimeError(f"Required environment variable {key!r} is not set")
    if len(val) < min_length:
        raise RuntimeError(f"{key!r} must be at least {min_length} characters")
    return val


def _validate_url(val):
    try:
        p = urlparse(val)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


UNIFI_URL      = _require_env("UNIFI_URL")
UNIFI_USERNAME = _require_env("UNIFI_USERNAME")
UNIFI_PASSWORD = _require_env("UNIFI_PASSWORD", min_length=8)
APP_PASSWORD   = _require_env("APP_PASSWORD", min_length=8)
SECRET_KEY     = _require_env("SECRET_KEY", min_length=32)

if not _validate_url(UNIFI_URL):
    raise RuntimeError("UNIFI_URL must be a valid http/https URL")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,  # Set True when serving over HTTPS
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

_POLICY_ID_RE = re.compile(r"^[a-f0-9]{24,64}$")


def get_unifi_session():
    s = requests.Session()
    s.verify = False
    r = s.post(
        f"{UNIFI_URL}/api/auth/login",
        json={"username": UNIFI_USERNAME, "password": UNIFI_PASSWORD},
        timeout=10,
    )
    r.raise_for_status()
    csrf = r.headers.get("X-Csrf-Token", "")
    if csrf:
        s.headers.update({"X-CSRF-Token": csrf})
    return s


def get_firewall_policies(s):
    r = s.get(f"{UNIFI_URL}/proxy/network/v2/api/site/default/firewall-policies", timeout=10)
    r.raise_for_status()
    return r.json()


def get_zone_names(s, policies):
    networks = {}
    try:
        r = s.get(f"{UNIFI_URL}/proxy/network/api/s/default/rest/networkconf", timeout=10)
        r.raise_for_status()
        data = r.json()
        entries = data.get("data", data) if isinstance(data, dict) else data
        networks = {e["_id"]: e.get("name", "") for e in entries if "_id" in e and e.get("name")}
    except Exception as exc:
        log.warning("networkconf failed: %s", exc)

    zone_nets: dict[str, set] = {}
    for p in policies:
        for side in ("source", "destination"):
            seg = p.get(side, {})
            zid = seg.get("zone_id")
            if not zid:
                continue
            for nid in seg.get("network_ids", []):
                name = networks.get(nid)
                if name:
                    zone_nets.setdefault(zid, set()).add(name)

    return {zid: "/".join(sorted(names)) for zid, names in zone_nets.items()}


def set_policy_enabled(s, policy_id, enabled):
    policies = get_firewall_policies(s)
    policy = next((p for p in policies if p.get("_id") == policy_id), None)
    if not policy:
        raise ValueError("Policy not found")
    policy["enabled"] = enabled
    r = s.put(
        f"{UNIFI_URL}/proxy/network/v2/api/site/default/firewall-policies/{policy_id}",
        json=policy,
        timeout=10,
    )
    r.raise_for_status()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.after_request
def apply_security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    return resp


def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    error = None
    if request.method == "POST":
        submitted = request.form.get("password", "")
        if len(submitted) > 1024:
            error = "Incorrect password"
        elif hmac.compare_digest(submitted, APP_PASSWORD):
            session.clear()  # prevent session fixation
            session["logged_in"] = True
            log.info("login success addr=%s", request.remote_addr)
            return redirect(url_for("index"))
        else:
            error = "Incorrect password"
            log.warning("login failed addr=%s", request.remote_addr)
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    resp = _no_cache(app.make_response(render_template("index.html")))
    return resp


@app.route("/api/rules")
@login_required
@limiter.limit("60 per minute")
def api_rules():
    try:
        s = get_unifi_session()
        policies = get_firewall_policies(s)
        zones = get_zone_names(s, policies)
        clean = []
        seen_ids = set()
        for p in policies:
            if p.get("predefined") is not False:
                continue
            pid = p.get("_id")
            if pid in seen_ids:
                continue
            seen_ids.add(pid)
            schedule = p.get("schedule", {})
            src_zone_id = p.get("source", {}).get("zone_id", "")
            dst_zone_id = p.get("destination", {}).get("zone_id", "")
            clean.append({
                "id": pid,
                "description": p.get("name", "Unnamed Policy"),
                "tooltip": p.get("description", ""),
                "enabled": p.get("enabled", False),
                "action": p.get("action", "").capitalize(),
                "schedule": schedule.get("mode", "ALWAYS").lower(),
                "short_id": pid[-8:] if pid else "",
                "source_zone": zones.get(src_zone_id) or src_zone_id[-4:] if src_zone_id else "",
                "dest_zone": zones.get(dst_zone_id) or dst_zone_id[-4:] if dst_zone_id else "",
            })
        return _no_cache(jsonify({"ok": True, "rules": clean}))
    except Exception:
        log.exception("failed to load rules")
        return jsonify({"ok": False, "error": "Failed to load rules"}), 500


@app.route("/api/rules/<rule_id>/toggle", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def api_toggle(rule_id):
    if not _POLICY_ID_RE.match(rule_id):
        return jsonify({"ok": False, "error": "Invalid rule ID"}), 400
    try:
        data = request.get_json(silent=True) or {}
        enabled = bool(data.get("enabled", False))
        s = get_unifi_session()
        set_policy_enabled(s, rule_id, enabled)
        log.info("rule_toggle id=%s enabled=%s addr=%s", rule_id, enabled, request.remote_addr)
        return _no_cache(jsonify({"ok": True, "enabled": enabled}))
    except Exception:
        log.exception("failed to toggle rule %s", rule_id)
        return jsonify({"ok": False, "error": "Toggle failed"}), 500


@app.route("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5055, debug=False)
