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


def _build_v2_to_integration_zone_map(s, site_id):
    """Returns {v2_zone_hex_id: integration_zone_uuid}."""
    try:
        nc_entries = _fetch_json(s, f"/proxy/network/api/s/{UNIFI_SITE}/rest/networkconf")
        int_zones = _integration_get(f"/sites/{site_id}/firewall/zones")
        int_networks = _integration_get(f"/sites/{site_id}/networks")
    except Exception as exc:
        log.warning("zone map: %s", exc)
        return {}

    int_net_name_to_zone = {n["name"]: n.get("zoneId") for n in int_networks if "name" in n}
    int_zone_name_to_uuid = {z["name"]: z["id"] for z in int_zones if "name" in z and "id" in z}

    nc_by_zone: dict[str, list] = {}
    for nc in nc_entries:
        v2_zid = nc.get("firewall_zone_id")
        if v2_zid:
            nc_by_zone.setdefault(v2_zid, []).append(nc)

    result = {}
    for v2_zid, nets in nc_by_zone.items():
        if all(n.get("purpose") == "wan" for n in nets):
            uuid = int_zone_name_to_uuid.get("External")
            if uuid:
                result[v2_zid] = uuid
        else:
            for nc in nets:
                uuid = int_net_name_to_zone.get(nc.get("name", ""))
                if uuid:
                    result[v2_zid] = uuid
                    break
    return result


def get_policy_ordering(v2_policies, zone_pairs, s):
    """Returns {v2_policy_id: position} for display-order sorting.

    Calls the integration API ordering endpoint per zone pair using correct
    integration zone UUIDs. Policies without an integration ID (nulls in the
    ordering response) fall back to their index value in the sort key, which
    keeps them after explicitly-positioned policies since index starts at 10000+.
    """
    if not UNIFI_API_KEY or not zone_pairs:
        return {}
    try:
        site_id = _get_integration_site_id()
        if not site_id:
            return {}

        zone_map = _build_v2_to_integration_zone_map(s, site_id)

        # Build integration policy UUID → v2 _id via policy name matching
        try:
            int_policies = _integration_get(f"/sites/{site_id}/firewall/policies")
        except Exception as exc:
            log.warning("integration policies fetch failed: %s", exc)
            int_policies = []
        int_name_to_uuid = {
            p["name"]: p["id"]
            for p in (int_policies if isinstance(int_policies, list) else [])
            if p.get("name") and p.get("id")
        }
        int_uuid_to_v2_id = {
            int_uuid: p["_id"]
            for p in v2_policies
            if p.get("name") and p.get("_id")
            for int_uuid in [int_name_to_uuid.get(p["name"])]
            if int_uuid
        }

        ordering = {}
        for src_v2, dst_v2 in zone_pairs:
            int_src = zone_map.get(src_v2)
            int_dst = zone_map.get(dst_v2)
            if not int_src or not int_dst:
                log.warning("no integration zone UUID for v2 pair %s->%s", src_v2, dst_v2)
                continue
            try:
                data = _integration_get(
                    f"/sites/{site_id}/firewall/policies/ordering"
                    f"?sourceFirewallZoneId={int_src}&destinationFirewallZoneId={int_dst}"
                )
                if isinstance(data, dict) and "orderedFirewallPolicyIds" in data:
                    ordered = data["orderedFirewallPolicyIds"]
                    ids_in_order = (
                        (ordered.get("beforeSystemDefined") or []) +
                        (ordered.get("afterSystemDefined") or [])
                    )
                    for pos, int_pid in enumerate(ids_in_order):
                        if int_pid is not None:
                            v2_id = int_uuid_to_v2_id.get(int_pid)
                            if v2_id:
                                ordering[v2_id] = pos
                elif isinstance(data, list):
                    for pos, item in enumerate(data):
                        pid = item if isinstance(item, str) else (
                            item.get("id") or item.get("_id") if isinstance(item, dict) else None
                        )
                        if pid:
                            v2_id = int_uuid_to_v2_id.get(pid, pid)
                            ordering[v2_id] = pos
            except Exception as exc:
                log.warning("ordering fetch failed for %s->%s: %s", int_src, int_dst, exc)
        return ordering
    except Exception as exc:
        log.warning("policy ordering failed: %s", exc)
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

        ordering = get_policy_ordering(policies, group_order, s)

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
    results = {}

    if UNIFI_API_KEY:
        try:
            s = get_unifi_session()
            site_id = _get_integration_site_id()
            results["resolved_site_id"] = site_id
            if site_id:
                policies = get_firewall_policies(s)
                seen: set = set()
                zone_pairs = []
                for p in policies:
                    if p.get("predefined") is not False:
                        continue
                    src = p.get("source", {}).get("zone_id", "")
                    dst = p.get("destination", {}).get("zone_id", "")
                    if src and dst and (src, dst) not in seen:
                        seen.add((src, dst))
                        zone_pairs.append((src, dst))

                zone_map = _build_v2_to_integration_zone_map(s, site_id)
                results["v2_to_integration_zone_map"] = zone_map

                int_zones = _integration_get(f"/sites/{site_id}/firewall/zones")
                zone_uuid_to_name = {z["id"]: z["name"] for z in int_zones if "id" in z}

                pair_results = {}
                for src, dst in zone_pairs:
                    int_src = zone_map.get(src)
                    int_dst = zone_map.get(dst)
                    if not int_src or not int_dst:
                        label = f"{src[-6:]}→{dst[-6:]} (unmapped)"
                        pair_results[label] = {"error": "zone not in map"}
                        continue
                    url = (
                        f"{UNIFI_URL}/proxy/network/integration/v1/sites/{site_id}"
                        f"/firewall/policies/ordering"
                        f"?sourceFirewallZoneId={int_src}&destinationFirewallZoneId={int_dst}"
                    )
                    r2 = requests.get(
                        url,
                        headers={"X-API-Key": UNIFI_API_KEY, "Accept": "application/json"},
                        verify=False,
                        timeout=10,
                    )
                    try:
                        body = r2.json()
                    except Exception:
                        body = r2.text
                    src_name = zone_uuid_to_name.get(int_src, src[-6:])
                    dst_name = zone_uuid_to_name.get(int_dst, dst[-6:])
                    pair_results[f"{src_name}→{dst_name}"] = {
                        "status": r2.status_code,
                        "body": body,
                    }
                results["integration_ordering"] = pair_results
        except Exception as exc:
            results["integration_error"] = str(exc)
    else:
        results["_api_key"] = "UNIFI_API_KEY not set"

    return _no_cache(jsonify(results))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5055, debug=False)
