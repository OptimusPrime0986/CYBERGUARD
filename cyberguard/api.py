"""Management API (/api/v1). Cookie sessions (server-side revocable) + CSRF header + role/ownership checks."""
import hmac, os, re, secrets, time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from flask import Blueprint, Flask, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

from . import alerts as al, auth2, coverage as cov, events as ev, scanner, tls
from .engine import _http
from .deployer import ConflictError, DeploymentError, NotFound
from .validation import MODES, ValidationError

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
DUMMY = generate_password_hash("not-a-real-password")
SAFE = ("GET", "HEAD", "OPTIONS")


class Http(Exception):
    def __init__(self, status, code, message, **extra):
        self.status, self.body = status, {"error": code, "message": message, **extra}


def create_app(dep, secret, cookie_secure=True, static_dir=None, login_limit=(5, 300), probe=None, alert_engine=None):
    store = dep.store
    if probe is None and hasattr(dep.engine, "public_url"):        # fetch through the proxy exactly like a visitor, with the site's Host
        probe = lambda host, path, method="GET": _http(dep.engine.public_url + path, {"Host": host}, full=True)
    ae = alert_engine or al.AlertEngine(store, al.smtp_sender())
    app = Flask(__name__, static_folder=None)
    app.config.update(SECRET_KEY=secret, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=cookie_secure, MAX_CONTENT_LENGTH=64 * 1024)
    bp, attempts = Blueprint("api", __name__, url_prefix="/api/v1"), {}   # login limiter: in-memory, single process

    @app.errorhandler(Http)
    def _http(e): return jsonify(e.body), e.status

    def auth(*roles, write=False):
        def deco(fn):
            @wraps(fn)
            def w(*a, **kw):
                sid = session.get("sid"); u = store.session_user(sid) if sid else None
                if not u or u["status"] != "active": raise Http(401, "unauthenticated", "Login required")
                if request.method not in SAFE and not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), session.get("csrf", "")):
                    raise Http(403, "csrf", "Missing or invalid CSRF token")
                if (roles and u["role"] not in roles) or (write and u["role"] == "analyst"):
                    store.audit(u["email"], None, "authz.denied", None, {"path": request.path, "method": request.method}, "denied", None)
                    raise Http(403, "forbidden", "Your role does not permit this action")
                g.user = u
                return fn(*a, **kw)
            return w
        return deco

    def site_access(sid):
        u = g.user
        if not store.get_site(sid) or (u["role"] != "admin" and not store.has_access(sid, u["id"])):
            raise Http(404, "not_found", "Site not found")       # same answer for 'missing' and 'not yours'

    def view(cfg):
        st, w = dep.protection_state(cfg["site_id"]), []
        if st["effective_mode"] == "disabled": w.append("WAF protection is DISABLED for this site.")
        if st["effective_mode"] == "monitoring": w.append("Monitoring only: attacks are detected but NOT blocked.")
        if st["sync_state"] != "in_sync": w.append(f"Configuration state is '{st['sync_state']}': protection cannot be confirmed.")
        if st["requested_status"] == "failed": w.append("The last requested change FAILED and was not applied; the previous policy is still in effect.")
        if g.user["role"] == "analyst":
            cfg = {k: v for k, v in cfg.items() if not k.startswith("origin_")}
        return {**cfg, "protection": st, "warnings": w}

    def run(sid, fn):
        try: return jsonify(fn())
        except ValidationError as e: raise Http(422, "validation_failed", "Validation failed", details=e.errors)
        except ConflictError as e: raise Http(409, "conflict", str(e))
        except NotFound as e: raise Http(404, "not_found", str(e))
        except DeploymentError as e:
            body = {"error": "deployment_failed", "message": f"Change was NOT applied ({e.stage}). Previous policy kept.",
                    "stage": e.stage, "detail": e.message[:500], "rolled_back": e.rolled_back}
            try:
                if sid: body["protection"] = dep.protection_state(sid)
            except NotFound:
                pass                                   # e.g. a brand-new site whose registration failed
            return jsonify(body), 502

    def body(): return request.get_json(silent=True) or {}

    # ---------- auth ----------
    @bp.post("/auth/login")
    def login():
        b, ip = body(), request.remote_addr
        email = str(b.get("email", "")).strip().lower(); key = (ip, email)
        recent = [t for t in attempts.get(key, []) if t > time.time() - login_limit[1]]
        if len(recent) >= login_limit[0]: raise Http(429, "rate_limited", "Too many attempts. Try again later.")
        u = store.get_user_by_email(email)
        ok = check_password_hash(u["password_hash"] if u else DUMMY, str(b.get("password", ""))) and u and u["status"] == "active"
        if ok and u["totp_enabled"]:
            code = str(b.get("code", "")).strip()
            if not code: raise Http(401, "totp_required", "Enter the 6-digit code from your authenticator app")
            step = auth2.verify(auth2.unseal(secret, u["totp_secret"]), code, u["totp_last_step"])
            if step is None: ok = False
            else: store.set_totp_step(u["id"], step)           # a code works once
        if not ok:
            attempts[key] = recent + [time.time()]
            store.audit(email[:100] or "?", None, "auth.login", None, None, "failed", None)
            raise Http(401, "invalid_credentials", "Invalid email or password")
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        store.create_session(sid, u["id"], (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat())
        session.clear(); session.update(sid=sid, csrf=csrf)
        store.audit(email, None, "auth.login", None, None, "success", None)
        return jsonify({"user": {"email": u["email"], "role": u["role"]}, "csrf": csrf})

    @bp.post("/auth/logout")
    @auth()
    def logout():
        store.delete_session(session.get("sid")); session.clear(); return jsonify({"ok": True})

    @bp.get("/auth/me")
    @auth()
    def me(): return jsonify({"user": {"email": g.user["email"], "role": g.user["role"], "totp_enabled": bool(store.get_user(g.user["id"])["totp_enabled"])}, "csrf": session["csrf"]})

    def audit(action, sid, prev, new, result="success"): store.audit(g.user["email"], sid, action, prev, new, result, None)

    @bp.post("/auth/2fa/setup")
    @auth()
    def tf_setup():
        u = store.get_user(g.user["id"])
        if u["totp_enabled"]: raise Http(409, "conflict", "Two-factor sign-in is already enabled")
        sec = auth2.new_secret(); store.set_totp(u["id"], auth2.seal(secret, sec), False)
        return jsonify({"secret": sec, "uri": auth2.uri(u["email"], sec)})

    def _verify_own(code):
        u = store.get_user(g.user["id"]); sec = auth2.unseal(secret, u["totp_secret"] or "")
        step = auth2.verify(sec, code, u["totp_last_step"]) if sec else None
        if step is None: raise Http(422, "invalid_code", "That code is not valid. Check the time on your device and try again.")
        return step

    @bp.post("/auth/2fa/enable")
    @auth()
    def tf_enable():
        step = _verify_own(body().get("code")); store.set_totp(g.user["id"], store.get_user(g.user["id"])["totp_secret"], True, step)
        audit("auth.2fa_enabled", None, None, None); return jsonify({"totp_enabled": True})

    @bp.post("/auth/2fa/disable")
    @auth()
    def tf_disable():
        _verify_own(body().get("code")); store.set_totp(g.user["id"], None, False)
        audit("auth.2fa_disabled", None, None, None); return jsonify({"totp_enabled": False})

    @bp.delete("/users/<int:uid>/2fa")
    @auth("admin")
    def tf_reset(uid):
        if not store.get_user(uid): raise Http(404, "not_found", "User not found")
        store.set_totp(uid, None, False); audit("user.2fa_reset", None, {"user_id": uid}, None); return jsonify({"ok": True})

    # ---------- users (admin) ----------
    @bp.get("/users")
    @auth("admin")
    def users(): return jsonify([dict(u, sites=store.accessible_sites(u["id"])) for u in store.list_users()])

    @bp.post("/users")
    @auth("admin")
    def new_user():
        b, errs = body(), []
        email = str(b.get("email", "")).strip().lower()
        if not EMAIL_RE.match(email): errs.append("valid email required")
        if len(str(b.get("password", ""))) < 12: errs.append("password must be at least 12 characters")
        if b.get("role") not in ("owner", "analyst", "admin"): errs.append("role must be admin, owner or analyst")
        sites = b.get("site_ids") or []
        if not isinstance(sites, list) or any(not store.get_site(s) for s in sites): errs.append("site_ids must reference existing sites")
        if store.get_user_by_email(email): errs.append("email already registered")
        if errs: raise Http(422, "validation_failed", "Validation failed", details=errs)
        uid = store.create_user(email, generate_password_hash(b["password"]), b["role"])
        for s in sites: store.grant(s, uid)
        store.audit(g.user["email"], None, "user.create", None, {"email": email, "role": b["role"], "sites": sites}, "success", None)
        return jsonify({"id": uid, "email": email, "role": b["role"]}), 201

    # ---------- sites ----------
    @bp.get("/sites")
    @auth()
    def sites():
        allowed = None if g.user["role"] == "admin" else set(store.accessible_sites(g.user["id"]))
        return jsonify([view(c) for c in store.list_sites() if allowed is None or c["site_id"] in allowed])

    @bp.post("/sites")
    @auth("admin")
    def add_site():
        b = body(); owner = b.pop("owner_email", None); policy = b.pop("policy", None)
        u = store.get_user_by_email(str(owner).lower()) if owner else None
        if owner and not u: raise Http(422, "validation_failed", "Validation failed", details=["owner_email is not a registered user"])
        def go():
            dep.register_site(g.user["email"], b, policy)
            if u: store.grant(b["site_id"], u["id"])
            return view(store.get_site(b["site_id"]))
        r = run(b.get("site_id"), go)
        return (r, 201) if not isinstance(r, tuple) else r

    @bp.get("/sites/<sid>")
    @auth()
    def site(sid): site_access(sid); return jsonify(view(store.get_site(sid)))

    @bp.delete("/sites/<sid>")
    @auth("admin")
    def del_site(sid):
        site_access(sid); return run(sid, lambda: (dep.remove_site(g.user["email"], sid), {"removed": sid})[1])

    @bp.get("/sites/<sid>/protection")
    @auth()
    def prot(sid): site_access(sid); return jsonify(dep.protection_state(sid))

    @bp.put("/sites/<sid>/protection")
    @auth(write=True)
    def set_prot(sid):
        site_access(sid); b = body()
        if b.get("mode") not in MODES or not isinstance(b.get("expected_version"), int) or isinstance(b.get("expected_version"), bool):
            raise Http(422, "validation_failed", "mode and integer expected_version are required", details=[f"mode in {MODES}"])
        cur = store.get_policy(sid, store.get_state(sid)["effective_version"])["config"]
        return run(sid, lambda: dep.set_policy(g.user["email"], sid, {**cur, "mode": b["mode"]}, b["expected_version"]))

    @bp.get("/sites/<sid>/policy")
    @auth()
    def pol(sid):
        site_access(sid); v = store.get_state(sid)["effective_version"]; return jsonify(store.get_policy(sid, v))

    @bp.put("/sites/<sid>/policy")
    @auth(write=True)
    def set_pol(sid):
        site_access(sid); b = body(); ev = b.pop("expected_version", None)
        if not isinstance(ev, int) or isinstance(ev, bool): raise Http(422, "validation_failed", "expected_version required")
        return run(sid, lambda: dep.set_policy(g.user["email"], sid, b, ev))

    @bp.get("/sites/<sid>/policy/versions")
    @auth()
    def versions(sid): site_access(sid); return jsonify(store.list_policies(sid)[::-1])

    @bp.post("/sites/<sid>/policy/rollback")
    @auth(write=True)
    def rollback(sid):
        site_access(sid); b = body()
        if not isinstance(b.get("to_version"), int) or not isinstance(b.get("expected_version"), int):
            raise Http(422, "validation_failed", "to_version and expected_version required")
        return run(sid, lambda: dep.rollback(g.user["email"], sid, b["to_version"], b["expected_version"]))

    @bp.get("/sites/<sid>/audit")
    @auth()
    def site_audit(sid):
        site_access(sid); lim = min(max(request.args.get("limit", 50, int), 1), 200); off = max(request.args.get("offset", 0, int), 0)
        rows = store.audit_list(sid)[::-1]
        return jsonify({"total": len(rows), "items": rows[off:off + lim]})

    @bp.get("/audit")
    @auth("admin")
    def all_audit(): return jsonify(store.audit_list()[::-1][:200])

    @bp.get("/sites/<sid>/health")
    @auth()
    def site_health(sid):
        site_access(sid)
        try: return jsonify(dep.site_health(sid))
        except Exception: return jsonify({"status": "unavailable", "detail": "health check failed"}), 503

    # ---------- analytics & events (real data from proxy logs) ----------
    def rng():
        r = request.args.get("range", "1h")
        if r not in ev.RANGES: raise Http(422, "validation_failed", f"range must be one of {list(ev.RANGES)}")
        return r

    def visible():
        ids = [c["site_id"] for c in store.list_sites()]
        return ids if g.user["role"] == "admin" else [i for i in ids if store.has_access(i, g.user["id"])]

    @bp.get("/analytics/overview")
    @auth()
    def overview():
        ids, r = visible(), rng()
        return jsonify({"range": r, "traffic": ev.traffic(store, ids, r), "security": ev.security(store, ids, r),
                        "per_site": ev.per_site(store, ids, r), "pipeline": ev.pipeline_status(store)})

    @bp.get("/sites/<sid>/analytics/traffic")
    @auth()
    def a_traffic(sid): site_access(sid); return jsonify(ev.traffic(store, [sid], rng()))

    @bp.get("/sites/<sid>/analytics/security")
    @auth()
    def a_security(sid): site_access(sid); return jsonify(ev.security(store, [sid], rng()))

    @bp.get("/sites/<sid>/events")
    @auth()
    def events(sid):
        site_access(sid); a = request.args
        lim = min(max(a.get("limit", 25, int), 1), 100); off = max(a.get("offset", 0, int), 0)
        return jsonify(ev.list_events(store, sid, {k: a.get(k) for k in ("type", "severity", "rule_id", "q", "since", "until")}, lim, off))

    @bp.get("/sites/<sid>/events/<eid>")
    @auth()
    def event(sid, eid):
        site_access(sid); e = ev.get_event(store, sid, eid)
        if not e: raise Http(404, "not_found", "Event not found")
        return jsonify(e)

    # ---------- certificates, alerts, scanner, coverage ----------
    @bp.get("/sites/<sid>/tls")
    @auth()
    def tls_status(sid): site_access(sid); return jsonify(dep.tls_status(sid))

    @bp.post("/sites/<sid>/tls")
    @auth("admin")
    def tls_install(sid):
        site_access(sid); b = body(); hosts = store.get_site(sid)["allowed_hostnames"]
        def go():
            if b.get("mode") == "self_signed": cert, key = tls.self_signed(hosts)
            else:
                cert, key = b.get("certificate"), b.get("private_key")
                if not all(isinstance(x, str) and 0 < len(x) < 30000 for x in (cert, key)): raise ValidationError(["certificate and private_key (PEM text) are required"])
            info = tls.inspect(cert, key, hosts); tls.install(dep.root, sid, cert, key)
            audit("tls.install", sid, None, {"self_signed": info["self_signed"], "not_after": info["not_after"], "san": info["san"]})
            if dep.policy_of(sid).https != "off": dep.reapply(g.user["email"])      # renewal: reload so the new certificate is served
            return dep.tls_status(sid)
        return run(sid, go)

    @bp.get("/sites/<sid>/alerts")
    @auth()
    def get_alerts(sid): site_access(sid); return jsonify(ae.settings(sid))

    @bp.put("/sites/<sid>/alerts")
    @auth(write=True)
    def put_alerts(sid):
        site_access(sid)
        def go():
            new = al.validate_settings(body()); prev = ae.settings(sid); store.kv_set(f"alerts:{sid}", new)
            audit("alerts.update", sid, {"enabled": prev["enabled"], "email": prev["email"]}, {"enabled": new["enabled"], "email": new["email"]}); return new
        return run(sid, go)

    @bp.post("/sites/<sid>/alerts/test")
    @auth(write=True)
    def test_alert(sid):
        site_access(sid)
        if not ae.settings(sid)["email"]: raise Http(422, "validation_failed", "Save an alert email address first")
        ok = ae.notify(sid, "test", "[CyberGuard] test alert", f"This is a test alert for {store.get_site(sid)['name']}. No action is needed.", force=True)
        return jsonify({"sent": ok, "notifications": store.list_notifications(sid, 1)})

    @bp.get("/sites/<sid>/notifications")
    @auth()
    def notifications(sid): site_access(sid); return jsonify(store.list_notifications(sid))

    @bp.get("/sites/<sid>/scan")
    @auth()
    def get_scan(sid): site_access(sid); return jsonify(store.kv_get(f"scan:{sid}") or {"findings": None})

    @bp.post("/sites/<sid>/scan")
    @auth(write=True)
    def run_scan(sid):
        site_access(sid)
        if not probe: raise Http(503, "unavailable", "No proxy connection is configured for scanning")
        cfg = store.get_site(sid)
        r = scanner.scan(cfg, dep.policy_of(sid), lambda path: probe(cfg["hostname"], path), dep.tls_status(sid))
        store.kv_set(f"scan:{sid}", r); audit("scan.run", sid, None, r.get("summary")); return jsonify(r)

    @bp.get("/coverage")
    @auth()
    def coverage(): return jsonify(cov.view(store))

    @bp.post("/coverage/run")
    @auth("admin")
    def coverage_run():
        if not probe: raise Http(503, "unavailable", "No proxy connection is configured")
        r = cov.run_tests(store, dep, probe); store.kv_set("coverage:last", r); audit("coverage.run", None, None, {"tests": len(r.get("results", {}))})
        return jsonify(cov.view(store))

    @bp.get("/health/live")
    def live(): return jsonify({"status": "live"})

    @bp.get("/health/ready")
    def ready():
        try: store._q("SELECT 1"); return jsonify({"status": "ready"})
        except Exception: return jsonify({"status": "not_ready"}), 503

    app.register_blueprint(bp)

    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def spa(path):
        if path.startswith("api/") or not static_dir: raise Http(404, "not_found", "Not found")
        f = Path(static_dir) / path
        return send_from_directory(static_dir, path) if path and f.is_file() else send_from_directory(static_dir, "index.html")

    @app.after_request
    def headers(r):
        r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                          "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"})
        if request.path.startswith("/api/"): r.headers["Cache-Control"] = "no-store"
        return r

    return app
