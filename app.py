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
from werkzeug.middleware.proxy_fix import ProxyFix

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


TRUST_PROXY   = os.environ.get("TRUST_PROXY", "").lower() in ("1", "true", "yes")

UNIFI_URL     = _require_env("UNIFI_URL")
UNIFI_SITE    = os.environ.get("UNIFI_SITE", "default").strip() or "default"
UNIFI_API_KEY = _require_env("UNIFI_API_KEY")
APP_PASSWORD  = _require_env("APP_PASSWORD", min_length=8)
SECRET_KEY    = _require_env("SECRET_KEY", min_length=32)

if not _validate_url(UNIFI_URL):
    raise RuntimeError("UNIFI_URL must be a valid http/https URL")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=TRUST_PROXY,
)

if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    log.info("proxy mode enabled: trusting 1 hop of X-Forwarded-* headers")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

_POLICY_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

_DAY_ORDER  = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _fmt_time(t):
    h, m = map(int, t.split(":"))
    period = "AM" if h < 12 else "PM"
    h12 = h % 12 or 12
    return f"{h12}:{m:02d}{period}" if m else f"{h12}{period}"


def _format_schedule(schedule):
    mode = schedule.get("mode", "ALWAYS")
    if mode == "ALWAYS":
        return "always"
    # Accept both snake_case and camelCase keys defensively
    days_raw = schedule.get("repeat_on_days") or schedule.get("repeatOnDays") or []
    days = [d for d in _DAY_ORDER if d in days_raw]
    if not days:
        return mode.lower()
    indices = [_DAY_ORDER.index(d) for d in days]
    consecutive = all(indices[i+1] - indices[i] == 1 for i in range(len(indices) - 1))
    day_str = (f"{_DAY_LABELS[indices[0]]}–{_DAY_LABELS[indices[-1]]}"
               if consecutive and len(days) > 1
               else ", ".join(_DAY_LABELS[i] for i in indices))
    start = schedule.get("time_range_start") or schedule.get("timeRangeStart")
    end   = schedule.get("time_range_end") or schedule.get("timeRangeEnd")
    time_all_day = schedule.get("time_all_day") or schedule.get("timeAllDay")
    if start and end and not time_all_day:
        return f"{day_str} {_fmt_time(start)}–{_fmt_time(end)}"
    return day_str


def _integration_request(method, path, **kwargs):
    r = requests.request(
        method,
        f"{UNIFI_URL}/proxy/network/integration/v1{path}",
        headers={"X-API-Key": UNIFI_API_KEY, "Accept": "application/json"},
        verify=False,
        timeout=10,
        **kwargs,
    )
    if not r.ok:
        log.error("integration API %s %s -> %s: %s", method, path, r.status_code, r.text[:500])
    r.raise_for_status()
    if not r.content:
        return None
    data = r.json()
    return data.get("data", data) if isinstance(data, dict) and "data" in data else data


def _get_site_id():
    sites = _integration_request("GET", "/sites")
    if not isinstance(sites, list):
        return None
    for site in sites:
        name = site.get("name", "")
        if name == UNIFI_SITE or name.lower() == "default":
            return site.get("id") or site.get("_id")
    if sites:
        return sites[0].get("id") or sites[0].get("_id")
    return None


def get_firewall_policies(site_id):
    return _integration_request("GET", f"/sites/{site_id}/firewall/policies")


def get_zone_names(site_id):
    try:
        zones = _integration_request("GET", f"/sites/{site_id}/firewall/zones")
        return {z["id"]: z["name"] for z in zones if "id" in z and "name" in z}
    except Exception as exc:
        log.warning("zone names fetch failed: %s", exc)
        return {}


_PUT_STRIP_FIELDS = {"id", "metadata", "loggingEnabled"}

def set_policy_enabled(site_id, policy_id, enabled):
    policy = _integration_request("GET", f"/sites/{site_id}/firewall/policies/{policy_id}")
    if not policy:
        raise ValueError("Policy not found")
    policy["enabled"] = enabled
    body = {k: v for k, v in policy.items() if k not in _PUT_STRIP_FIELDS}
    _integration_request("PUT", f"/sites/{site_id}/firewall/policies/{policy_id}", json=body)


def get_policy_ordering(zone_pairs, site_id):
    if not zone_pairs:
        return {}
    ordering = {}
    for src_zid, dst_zid in zone_pairs:
        try:
            data = _integration_request(
                "GET",
                f"/sites/{site_id}/firewall/policies/ordering"
                f"?sourceFirewallZoneId={src_zid}&destinationFirewallZoneId={dst_zid}"
            )
            if isinstance(data, dict) and "orderedFirewallPolicyIds" in data:
                ordered = data["orderedFirewallPolicyIds"]
                ids_in_order = (
                    (ordered.get("beforeSystemDefined") or []) +
                    (ordered.get("afterSystemDefined") or [])
                )
                for pos, pid in enumerate(ids_in_order):
                    if pid is not None:
                        ordering[pid] = pos
            elif isinstance(data, list):
                for pos, item in enumerate(data):
                    pid = item if isinstance(item, str) else (
                        item.get("id") if isinstance(item, dict) else None
                    )
                    if pid:
                        ordering[pid] = pos
        except Exception as exc:
            log.warning("ordering fetch failed for %s->%s: %s", src_zid, dst_zid, exc)
    return ordering


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
        site_id = _get_site_id()
        if not site_id:
            return jsonify({"ok": False, "error": "Could not resolve UniFi site"}), 500

        policies = get_firewall_policies(site_id)
        zones = get_zone_names(site_id)

        group_order = []
        group_map = {}
        seen_ids = set()

        for p in policies:
            if p.get("metadata", {}).get("origin") == "SYSTEM_DEFINED":
                continue
            pid = p.get("id")
            if pid and pid in seen_ids:
                continue
            if pid:
                seen_ids.add(pid)

            src_zone_id = p.get("source", {}).get("zoneId", "")
            dst_zone_id = p.get("destination", {}).get("zoneId", "")
            key = (src_zone_id, dst_zone_id)

            src_name = zones.get(src_zone_id) or (src_zone_id[-4:] if src_zone_id else "")
            dst_name = zones.get(dst_zone_id) or (dst_zone_id[-4:] if dst_zone_id else "")
            label = src_name if src_name == dst_name else f"{src_name} → {dst_name}"

            if key not in group_map:
                group_order.append(key)
                group_map[key] = {"label": label, "rules": []}

            group_map[key]["rules"].append({
                "id": pid,
                "description": p.get("name", "Unnamed Policy"),
                "tooltip": p.get("description", ""),
                "enabled": p.get("enabled", False),
                "action": p.get("action", {}).get("type", "").capitalize(),
                "schedule": _format_schedule(p.get("schedule", {})),
                "index": p.get("index", 0),
            })

        ordering = get_policy_ordering(group_order, site_id)

        groups = []
        for key in group_order:
            g = group_map[key]
            if ordering:
                g["rules"].sort(key=lambda r: ordering.get(r["id"], r["index"]))
            else:
                g["rules"].sort(key=lambda r: r["index"])
            groups.append(g)

        return _no_cache(jsonify({"ok": True, "groups": groups, "ordering_active": bool(ordering)}))
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
        site_id = _get_site_id()
        if not site_id:
            return jsonify({"ok": False, "error": "Could not resolve UniFi site"}), 500
        set_policy_enabled(site_id, rule_id, enabled)
        log.info("rule_toggle id=%s enabled=%s addr=%s", rule_id, enabled, request.remote_addr)
        return _no_cache(jsonify({"ok": True, "enabled": enabled}))
    except Exception:
        log.exception("failed to toggle rule %s", rule_id)
        return jsonify({"ok": False, "error": "Toggle failed"}), 500


@app.route("/health")
def health():
    return jsonify({"ok": True})


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain"}


@app.route("/api/debug/raw-policies")
@login_required
def api_debug_raw_policies():
    site_id = _get_site_id()
    policies = get_firewall_policies(site_id)
    return _no_cache(jsonify(policies))


@app.route("/api/debug/zones")
@login_required
def api_debug_zones():
    site_id = _get_site_id()
    results = {}
    for path in [
        f"/sites/{site_id}/firewall/zones",
        f"/sites/{site_id}/networks",
    ]:
        try:
            results[path] = _integration_request("GET", path)
        except Exception as exc:
            results[path] = {"error": str(exc)}
    return _no_cache(jsonify(results))


@app.route("/api/debug/policy-ordering")
@login_required
def api_debug_policy_ordering():
    results = {}
    try:
        site_id = _get_site_id()
        results["resolved_site_id"] = site_id
        if site_id:
            policies = get_firewall_policies(site_id)
            zones = get_zone_names(site_id)

            seen: set = set()
            zone_pairs = []
            for p in policies:
                src = p.get("source", {}).get("zoneId", "")
                dst = p.get("destination", {}).get("zoneId", "")
                if src and dst and (src, dst) not in seen:
                    seen.add((src, dst))
                    zone_pairs.append((src, dst))

            pair_results = {}
            for src, dst in zone_pairs:
                src_name = zones.get(src, src[-6:] if src else "?")
                dst_name = zones.get(dst, dst[-6:] if dst else "?")
                try:
                    body = _integration_request(
                        "GET",
                        f"/sites/{site_id}/firewall/policies/ordering"
                        f"?sourceFirewallZoneId={src}&destinationFirewallZoneId={dst}"
                    )
                    pair_results[f"{src_name}→{dst_name}"] = {"body": body}
                except Exception as exc:
                    pair_results[f"{src_name}→{dst_name}"] = {"error": str(exc)}
            results["integration_ordering"] = pair_results
    except Exception as exc:
        results["integration_error"] = str(exc)
    return _no_cache(jsonify(results))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5055, debug=False)
