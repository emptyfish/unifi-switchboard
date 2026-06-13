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


TRUST_PROXY    = os.environ.get("TRUST_PROXY", "").lower() in ("1", "true", "yes")

UNIFI_URL      = _require_env("UNIFI_URL")
UNIFI_SITE     = os.environ.get("UNIFI_SITE", "default").strip() or "default"
UNIFI_API_KEY  = os.environ.get("UNIFI_API_KEY", "").strip()
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
    days = [d for d in _DAY_ORDER if d in schedule.get("repeat_on_days", [])]
    if not days:
        return mode.lower()
    indices = [_DAY_ORDER.index(d) for d in days]
    consecutive = all(indices[i+1] - indices[i] == 1 for i in range(len(indices) - 1))
    day_str = (f"{_DAY_LABELS[indices[0]]}–{_DAY_LABELS[indices[-1]]}"
               if consecutive and len(days) > 1
               else ", ".join(_DAY_LABELS[i] for i in indices))
    start = schedule.get("time_range_start")
    end   = schedule.get("time_range_end")
    if start and end and not schedule.get("time_all_day"):
        return f"{day_str} {_fmt_time(start)}–{_fmt_time(end)}"
    return day_str


def get_firewall_policies(s):
    r = s.get(f"{UNIFI_URL}/proxy/network/v2/api/site/{UNIFI_SITE}/firewall-policies", timeout=10)
    r.raise_for_status()
    return r.json()


def _fetch_json(s, path):
    r = s.get(f"{UNIFI_URL}{path}", timeout=10)
    r.raise_for_status()
    data = r.json()
    return data.get("data", data) if isinstance(data, dict) and "data" in data else data


def _integration_get(path):
    r = requests.get(
        f"{UNIFI_URL}/proxy/network/integration/v1{path}",
        headers={"X-API-Key": UNIFI_API_KEY, "Accept": "application/json"},
        verify=False,
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    return data.get("data", data) if isinstance(data, dict) and "data" in data else data


def _get_integration_site_id():
    sites = _integration_get("/sites")
    if not isinstance(sites, list):
        return None
    for site in sites:
        name = site.get("name", "")
        if name == UNIFI_SITE or name.lower() == "default":
            return site.get("id") or site.get("_id")
    if sites:
        return sites[0].get("id") or sites[0].get("_id")
    return None


def get_policy_ordering(zone_pairs):
    if not UNIFI_API_KEY or not zone_pairs:
        return {}
    try:
        site_id = _get_integration_site_id()
        if not site_id:
            log.warning("policy ordering: could not resolve integration site ID")
            return {}
        ordering = {}
        for src_zone_id, dst_zone_id in zone_pairs:
            try:
                data = _integration_get(
                    f"/sites/{site_id}/firewall/policies/ordering"
                    f"?sourceFirewallZoneId={src_zone_id}&destinationFirewallZoneId={dst_zone_id}"
                )
                if isinstance(data, list):
                    for pos, item in enumerate(data):
                        if isinstance(item, str):
                            ordering[item] = pos
                        elif isinstance(item, dict):
                            pid = item.get("id") or item.get("_id") or item.get("policyId")
                            if pid:
                                ordering[pid] = item.get("order", pos)
            except Exception as exc:
                log.warning("ordering fetch failed for pair %s->%s: %s", src_zone_id, dst_zone_id, exc)
        return ordering
    except Exception as exc:
        log.warning("policy ordering fetch failed: %s", exc)
        return {}


def get_zone_names(s, _policies=None):
    try:
        entries = _fetch_json(s, f"/proxy/network/api/s/{UNIFI_SITE}/rest/networkconf")
    except Exception as exc:
        log.warning("networkconf failed: %s", exc)
        return {}

    zone_groups: dict[str, list] = {}
    for e in entries:
        zid = e.get("firewall_zone_id")
        if zid and e.get("name"):
            zone_groups.setdefault(zid, []).append(e)

    result = {}
    for zid, nets in zone_groups.items():
        if all(n.get("purpose") == "wan" for n in nets):
            result[zid] = "WAN"
        else:
            result[zid] = "/".join(n["name"] for n in nets if n.get("name"))
    return result


def set_policy_enabled(s, policy_id, enabled):
    policies = get_firewall_policies(s)
    policy = next((p for p in policies if p.get("_id") == policy_id), None)
    if not policy:
        raise ValueError("Policy not found")
    policy["enabled"] = enabled
    r = s.put(
        f"{UNIFI_URL}/proxy/network/v2/api/site/{UNIFI_SITE}/firewall-policies/{policy_id}",
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
        zones = get_zone_names(s)

        group_order = []
        group_map = {}
        seen_ids = set()

        for p in policies:
            if p.get("predefined") is not False:
                continue
            pid = p.get("_id")
            if pid in seen_ids:
                continue
            seen_ids.add(pid)

            src_zone_id = p.get("source", {}).get("zone_id", "")
            dst_zone_id = p.get("destination", {}).get("zone_id", "")
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
                "action": p.get("action", "").capitalize(),
                "schedule": _format_schedule(p.get("schedule", {})),
                "index": p.get("index", 0),
            })

        ordering = get_policy_ordering(group_order)

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


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain"}


@app.route("/api/debug/raw-policies")
@login_required
def api_debug_raw_policies():
    s = get_unifi_session()
    policies = get_firewall_policies(s)
    user_policies = [p for p in policies if p.get("predefined") is False]
    return _no_cache(jsonify(user_policies))


@app.route("/api/debug/zones")
@login_required
def api_debug_zones():
    s = get_unifi_session()
    results = {}
    for path in [
        f"/proxy/network/api/s/{UNIFI_SITE}/rest/networkconf",
    ]:
        try:
            results[path] = _fetch_json(s, path)
        except Exception as exc:
            results[path] = {"error": str(exc)}
    return _no_cache(jsonify(results))


@app.route("/api/debug/policy-ordering")
@login_required
def api_debug_policy_ordering():
    s = get_unifi_session()
    results = {}

    # Discover the v1 site ID (may differ from legacy "default")
    site_ids = [UNIFI_SITE]
    try:
        sites_data = _fetch_json(s, "/proxy/network/v1/api/sites")
        if isinstance(sites_data, list):
            for site in sites_data:
                sid = site.get("id") or site.get("_id") or site.get("name")
                if sid and sid not in site_ids:
                    site_ids.append(sid)
        results["_sites"] = sites_data
    except Exception as exc:
        results["_sites"] = {"error": str(exc)}

    for site_id in site_ids:
        for path in [
            f"/proxy/network/v2/api/site/{site_id}/firewall/policies/ordering",
            f"/proxy/network/v2/api/site/{site_id}/firewall-policies/ordering",
            f"/proxy/network/integration/v1/sites/{site_id}/firewall/policies/ordering",
            f"/proxy/network/v1/sites/{site_id}/firewall/policies/ordering",
        ]:
            try:
                results[path] = _fetch_json(s, path)
            except Exception as exc:
                results[path] = {"error": str(exc)}

    if UNIFI_API_KEY:
        try:
            integration_sites = _integration_get("/sites")
            results["integration_sites"] = integration_sites
            site_id = _get_integration_site_id()
            results["resolved_site_id"] = site_id
            if site_id:
                # Fetch ordering for all zone pairs found in current policies
                s2 = get_unifi_session()
                policies = get_firewall_policies(s2)
                seen = set()
                zone_pairs = []
                for p in policies:
                    if p.get("predefined") is not False:
                        continue
                    src = p.get("source", {}).get("zone_id", "")
                    dst = p.get("destination", {}).get("zone_id", "")
                    if src and dst and (src, dst) not in seen:
                        seen.add((src, dst))
                        zone_pairs.append((src, dst))
                pair_results = {}
                for src, dst in zone_pairs:
                    try:
                        pair_results[f"{src[-6:]}→{dst[-6:]}"] = _integration_get(
                            f"/sites/{site_id}/firewall/policies/ordering"
                            f"?sourceFirewallZoneId={src}&destinationFirewallZoneId={dst}"
                        )
                    except Exception as exc:
                        pair_results[f"{src[-6:]}→{dst[-6:]}"] = {"error": str(exc)}
                results["integration_ordering"] = pair_results
        except Exception as exc:
            results["integration_error"] = str(exc)
    else:
        results["_api_key"] = "UNIFI_API_KEY not set"

    return _no_cache(jsonify(results))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5055, debug=False)
