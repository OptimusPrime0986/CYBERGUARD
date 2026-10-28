import base64, json, sqlite3, time
from datetime import datetime, timedelta, timezone
import pytest
from cyberguard import alerts as al, auth2, coverage as cov, events as ev, scanner
from cyberguard.alerts import AlertEngine
from cyberguard.api import create_app
from cyberguard.deployer import DeploymentError
from cyberguard.store import Store
from cyberguard.validation import Policy, ValidationError
from .conftest import site
from .test_api import C, PW, world  # noqa: F401  (world is a fixture)
from .test_events import access, pipe, w  # noqa: F401


# ---------------- two-factor ----------------
def test_totp_matches_rfc6238_vector_and_rejects_replay():
    sec = base64.b32encode(b"12345678901234567890").decode()
    assert auth2.code_at(sec, 59 // 30) == "287082"
    assert auth2.verify(sec, "287082", now=59) == 1
    assert auth2.verify(sec, "287082", last_step=1, now=59) is None          # same step cannot be reused
    assert auth2.verify(sec, "287082", now=59 + 300) is None                 # outside the +/-1 step window
    assert auth2.verify(sec, "12345", now=59) is None and auth2.verify(sec, "abcdef", now=59) is None

def test_totp_secret_is_encrypted_at_rest():
    s = auth2.new_secret(); blob = auth2.seal("k" * 40, s)
    assert s not in blob and auth2.unseal("k" * 40, blob) == s and auth2.unseal("other" * 8, blob) is None

def test_two_factor_login_flow(world):
    app, store = world["app"], world["store"]
    c = world["login"]("own1@x.io"); step = int(time.time() // 30)
    sec = c.req("POST", "/auth/2fa/setup").get_json()["secret"]
    assert c.req("POST", "/auth/2fa/enable", {"code": "000000"}).status_code == 422
    assert c.req("POST", "/auth/2fa/enable", {"code": auth2.code_at(sec, step - 1)}).status_code == 200
    assert c.req("GET", "/auth/me").get_json()["user"]["totp_enabled"] is True
    assert c.req("POST", "/auth/2fa/setup").status_code == 409
    c.req("POST", "/auth/logout")
    n = C(app)
    r = n.login("own1@x.io"); assert r.status_code == 401 and r.get_json()["error"] == "totp_required"      # password right, code missing
    n2 = C(app); assert n2.c.post("/api/v1/auth/login", json={"email": "own1@x.io", "password": PW, "code": "123456"}).status_code == 401
    ok = n2.c.post("/api/v1/auth/login", json={"email": "own1@x.io", "password": PW, "code": auth2.code_at(sec, step)})
    assert ok.status_code == 200
    again = C(app).c.post("/api/v1/auth/login", json={"email": "own1@x.io", "password": PW, "code": auth2.code_at(sec, step)})
    assert again.status_code == 401                                                                       # replayed code refused
    n2.csrf = ok.get_json()["csrf"]
    assert n2.req("POST", "/auth/2fa/disable", {"code": auth2.code_at(sec, step + 1)}).status_code == 200

def test_admin_can_reset_a_users_two_factor(world):
    c = world["login"]("own2@x.io"); c.req("POST", "/auth/2fa/setup")
    uid = world["store"].get_user_by_email("own2@x.io")["id"]; sec = auth2.unseal("s" * 40, world["store"].get_user(uid)["totp_secret"])
    c.req("POST", "/auth/2fa/enable", {"code": auth2.code_at(sec, int(time.time() // 30))})
    assert world["adm"].req("DELETE", f"/users/{uid}/2fa").status_code == 200 and not world["store"].get_user(uid)["totp_enabled"]
    assert world["login"]("own2@x.io")                                                                    # can sign in with password only again
    assert world["login"]("own1@x.io").req("DELETE", f"/users/{uid}/2fa").status_code == 403


# ---------------- migration & rate-limit counting ----------------
def test_old_database_is_migrated_without_losing_data(tmp_path):
    p = tmp_path / "old.db"; db = sqlite3.connect(p)
    db.executescript("""CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      role TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL);
      CREATE TABLE traffic_minute(site_id TEXT NOT NULL, minute TEXT NOT NULL, total INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
      rejected INTEGER NOT NULL DEFAULT 0, s2 INTEGER NOT NULL DEFAULT 0, s3 INTEGER NOT NULL DEFAULT 0, s4 INTEGER NOT NULL DEFAULT 0, s5 INTEGER NOT NULL DEFAULT 0,
      lat_sum REAL NOT NULL DEFAULT 0, lat_max REAL NOT NULL DEFAULT 0, PRIMARY KEY(site_id, minute));
      INSERT INTO users(email,password_hash,role,created_at) VALUES('a@x.io','h','admin','t'); INSERT INTO traffic_minute(site_id,minute,total) VALUES('s','2026-01-01T00:00',7);""")
    db.commit(); db.close()
    st = Store(str(p))
    assert st._q("SELECT email, totp_enabled FROM users") == [{"email": "a@x.io", "totp_enabled": 0}]
    assert st._q("SELECT total, limited FROM traffic_minute") == [{"total": 7, "limited": 0}]
    Store(str(p))                                                                                          # second open is a no-op

def test_rate_limited_requests_are_counted_separately(pipe):
    store, ing, d = pipe
    w(d, "access", access("a", status=200, up="200"), access("l1", status=429), access("l2", status=429), access("o", status=429, up="429"))
    ing.run_once()
    t = ev.traffic(store, ["shop"], "15m")["totals"]
    assert (t["total"], t["rate_limited"], t["allowed"], t["blocked"]) == (4, 2, 2, 0)     # a 429 from the origin is not ours


# ---------------- alerts ----------------
CFG = {"enabled": True, "email": "ops@example.com", "cooldown_minutes": 15}

@pytest.mark.parametrize("bad", [{"enabled": True}, {"email": "a@b"}, {"email": "x@y.co,z@y.co"}, {"cooldown_minutes": 0}, {"kinds": {"nope": {"on": True}}},
                                 {"kinds": {"high_severity": {"threshold": 0}}}, {"kinds": {"deploy_failed": {"threshold": 3}}}, {"bogus": 1}])
def test_alert_settings_validation(bad):
    with pytest.raises(ValidationError): al.validate_settings(bad)

class Clock:
    def __init__(self): self.t = datetime.now(timezone.utc)
    def __call__(self): return self.t

def mk(env, sent, clock=None):
    dep, eng, store, _ = env
    dep.register_site("a", site("shop", "shop.example.com"), {"mode": "blocking"})
    store.kv_set("alerts:shop", al.validate_settings(CFG))
    def send(to, subject, body): sent.append((to, subject, body))
    return dep, eng, store, AlertEngine(store, send, now=clock or Clock())

def add_events(store, n, sev="critical", at=None, tag=""):
    for i in range(n):
        store._x("INSERT INTO waf_events(id,site_id,ts,event_type,rule_id,rule_ids,message,severity,category,path,query) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                 (f"e{sev}{i}{tag}", "shop", (at or datetime.now(timezone.utc)).isoformat(), "blocked", "942100", "[]", "SQLi", sev, "sqli", "/search", "q=UNION SELECT password"))

def test_threshold_alert_dedupes_then_repeats_after_cooldown_and_leaks_nothing(env):
    sent, clock = [], Clock(); dep, eng, store, eng2 = mk(env, sent, clock)
    add_events(store, 4); eng2.run_once(); assert sent == []                      # below threshold (5)
    add_events(store, 2, "high"); eng2.run_once(); eng2.run_once()
    assert len(sent) == 1 and "6 critical/high firewall detections" in sent[0][1]
    assert "UNION" not in sent[0][2] and "password" not in sent[0][2] and "/search" not in sent[0][2]       # counts only
    clock.t += timedelta(minutes=16); eng2.run_once(); assert len(sent) == 1               # old events left the 5-minute window
    add_events(store, 7, at=clock.t, tag="later"); eng2.run_once(); assert len(sent) == 2 and "7 critical/high" in sent[1][1]
    assert [n["status"] for n in store.list_notifications("shop")] == ["sent", "sent"]

def test_blocked_spike_and_origin_error_alerts_use_traffic_counts(env):
    sent = []; dep, eng, store, ae = mk(env, sent)
    m = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    store._x("INSERT INTO traffic_minute(site_id,minute,total,blocked,s5,limited) VALUES('shop',?,100,25,6,11)", (m,))
    ae.run_once(); subjects = " | ".join(s[1] for s in sent)
    assert "25 blocked requests" in subjects and "6 origin server errors" in subjects and "11 rate-limited requests" in subjects

def test_mode_reduction_and_failed_change_alert_immediately(env):
    sent = []; dep, eng, store, ae = mk(env, sent)
    ae.run_once(); sent.clear()
    dep.set_policy("alice", "shop", {"mode": "disabled"}, 1); ae.run_once()
    assert len(sent) == 1 and "protection reduced to 'disabled'" in sent[0][1] and "alice" in sent[0][2]
    eng.fail_validate = True
    with pytest.raises(DeploymentError): dep.set_policy("alice", "shop", {"mode": "blocking"}, 2)
    ae.run_once(); assert "policy change failed" in sent[-1][1] and "NOT applied" in sent[-1][2]
    n = len(sent); ae.run_once(); assert len(sent) == n                              # audit cursor: no repeat

def test_disabled_alerts_send_nothing_and_failures_are_recorded_not_hidden(env):
    sent = []; dep, eng, store, ae = mk(env, sent)
    add_events(store, 9); store.kv_set("alerts:shop", al.validate_settings({"enabled": False})); ae.run_once(); assert sent == []
    store.kv_set("alerts:shop", al.validate_settings(CFG))
    boom = AlertEngine(store, lambda *a: (_ for _ in ()).throw(ConnectionRefusedError("smtp down")), now=ae.now); boom.run_once()
    n = store.list_notifications("shop")[0]; assert n["status"] == "failed" and "smtp down" in n["error"]
    nosmtp = AlertEngine(store, None, now=Clock()); nosmtp.notify("shop", "test", "s", "b", force=True)
    assert "SMTP is not configured" in store.list_notifications("shop")[0]["error"]

def test_pipeline_stall_alert(env):
    sent = []; dep, eng, store, ae = mk(env, sent)
    store._x("INSERT INTO ingest_state(name,last_run_at,lines) VALUES('access',?,1)", ((datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),))
    ae.run_once(); assert any("event pipeline stalled" in s[1] for s in sent)


# ---------------- scanner ----------------
GOOD = {"x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()", "content-security-policy": "default-src 'self'"}

def fetcher(headers, exposed=()):
    return lambda path: (200 if path in exposed else 404, headers, "") if path != "/" else (200, headers, "")

def sc(policy, headers=GOOD, exposed=(), tls_status=None):
    r = scanner.scan({}, policy, fetcher(headers, exposed), tls_status or {"installed": False}); return r, {f["id"]: f for f in r["findings"]}

def test_scanner_reports_gaps_with_owasp_category_and_fixes():
    r, f = sc(Policy(), headers={"server": "nginx/1.25.3", "x-powered-by": "PHP/8.1"}, exposed=["/.git/config"])
    for k in ("hdr-nosniff", "hdr-frame", "hdr-referrer", "hdr-permissions", "banner", "sensitive-files", "https"): assert f[k]["status"] == "fail", k
    assert f["hdr-csp"]["status"] == "warn" and f["banner"]["detail"].startswith("Reveals: nginx/1.25.3") and "/.git/config" in f["sensitive-files"]["detail"]
    assert f["ratelimit"]["status"] == "warn" and all(x["owasp"].startswith("A") and x["id"] for x in r["findings"]) and r["note"].startswith("Configuration findings")

def test_scanner_passes_a_hardened_site():
    p = Policy(https="redirect", hsts=True, rate_limits=({"name": "l", "path": "/login", "per_minute": 5, "burst": 1},))
    r, f = sc(p, tls_status={"installed": True, "days_left": 60, "self_signed": False})
    assert {k: f[k]["status"] for k in ("hdr-nosniff", "hdr-frame", "hdr-csp", "banner", "sensitive-files", "https", "hsts", "cert", "mode", "errors", "ratelimit")} == {k: "pass" for k in ("hdr-nosniff", "hdr-frame", "hdr-csp", "banner", "sensitive-files", "https", "hsts", "cert", "mode", "errors", "ratelimit")}
    assert sc(p, tls_status={"installed": True, "days_left": 60, "self_signed": True})[1]["cert"]["status"] == "warn"

def test_scanner_flags_weak_config_and_unreachable_site():
    p = Policy(mode="disabled", generic_errors=False, anomaly_threshold=20, exclusions=({"rule_id": "942100", "path": None, "expires": "2020-01-01", "reason": "r"},))
    _, f = sc(p); assert (f["mode"]["status"], f["errors"]["status"], f["threshold"]["status"], f["exclusions"]["status"]) == ("fail", "warn", "warn", "warn")
    assert scanner.scan({}, Policy(), lambda p: (0, {}, "refused"), {})["error"]


# ---------------- coverage registry ----------------
def build_probe(dep, store, state):
    def probe(host, path, method="GET"):
        sid = "bank" if host.startswith("bank.") else "shop"; p = dep.policy_of(sid)
        if path.startswith("/report"):
            return (500, {}, "Something went wrong" if p.generic_errors else "Traceback (most recent call last)")
        if path.startswith("/login") or path.startswith("/search?q=rate"):
            state["n"] = state.get("n", 0) + 1; return (429 if state["n"] > 4 else 200, {}, "")
        if any(x in path for x in ("UNION", "script", "passwd", "../", "/.git")):
            if p.mode == "blocking":
                store._x("INSERT OR IGNORE INTO waf_events(id,site_id,ts,event_type,rule_id,rule_ids,message,severity,category) VALUES(?,?,?,?,?,?,?,?,?)",
                         (f"t{time.time_ns()}", sid, datetime.now(timezone.utc).isoformat(), "blocked", "942100", "[]", "m", "critical", "sqli"))
                return (403, {}, "")
            return (200, {}, "")
        if path == "/account?id=3": return (302, {}, "")
        return (200, ({k: v for k, v in GOOD.items() if k != "content-security-policy"} if p.security_headers else {"server": "nginx"}), "")
    return probe

def cov_world(env, **shop_policy):
    dep, eng, store, _ = env
    dep.register_site("a", site("bank", "bank.localhost"), {"mode": "blocking"})
    dep.register_site("a", site("shop", "shop.localhost"), {"mode": "blocking", **shop_policy})
    return dep, store

def test_coverage_blocking_run_records_real_statuses(env):
    dep, store = cov_world(env, rate_limits=[{"name": "login", "path": "/login", "per_minute": 5, "burst": 1}])
    r = cov.run_tests(store, dep, build_probe(dep, store, {}), sleep=lambda s: None)["results"]
    for t in ("A05-sqli-union", "A05-xss", "A05-sqli-numeric", "A05-cmdi", "A01-traversal", "A01-restricted-file", "A02-headers", "A02-banner", "A10-errors", "A09-events", "A07-ratelimit"):
        assert r[t]["status"] == "pass", (t, r[t])
    assert r["A01-idor"]["status"] == "gap" and "application" in r["A01-idor"]["detail"]
    assert r["A04-https"]["status"] == "not_configured"

def test_coverage_never_marks_attack_tests_passed_when_not_blocking(env):
    dep, store = cov_world(env); dep.set_policy("a", "shop", {"mode": "monitoring"}, 1); dep.set_policy("a", "bank", {"mode": "monitoring"}, 1)
    r = cov.run_tests(store, dep, build_probe(dep, store, {}), sleep=lambda s: None)["results"]
    assert all(r[t]["status"] == "skipped" for t in ("A05-sqli-union", "A05-xss", "A01-traversal", "A09-events"))
    assert r["A07-ratelimit"]["status"] == "not_configured"

def test_coverage_fails_when_the_firewall_does_not_block_and_when_events_are_missing(env):
    dep, store = cov_world(env); probe = build_probe(dep, store, {})
    leaky = lambda host, path, method="GET": (200, {}, "") if "UNION" in path else probe(host, path, method)
    assert cov.run_tests(store, dep, leaky, sleep=lambda s: None, wait_events=0)["results"]["A05-sqli-union"]["status"] == "fail"
    silent = lambda host, path, method="GET": (403, {}, "") if any(x in path for x in ("UNION", "script", "passwd", "../", "/.git")) else probe(host, path, method)
    assert cov.run_tests(store, dep, silent, sleep=lambda s: None, wait_events=0)["results"]["A09-events"]["status"] == "fail"

def test_coverage_verdicts_and_requirements(env):
    dep, store = env[0], env[2]
    assert "Register the demo sites" in cov.run_tests(store, dep, lambda *a: (0, {}, ""))["error"]
    v = cov.view(store); by = {c["id"]: c for c in v["categories"]}
    assert len(by) == 10 and by["A03"]["verdict"] == "no_waf_control" and by["A05"]["verdict"] == "not_tested"
    dep, store = cov_world(env, rate_limits=[{"name": "login", "path": "/login", "per_minute": 5, "burst": 1}])
    store.kv_set("coverage:last", cov.run_tests(store, dep, build_probe(dep, store, {}), sleep=lambda s: None))
    by = {c["id"]: c for c in cov.view(store)["categories"]}
    assert by["A05"]["verdict"] == "verified" and by["A07"]["verdict"] == "verified" and by["A01"]["verdict"] == "partial"      # IDOR gap keeps A01 honest
    assert by["A04"]["verdict"] == "not_verified" and by["A06"]["verdict"] == "no_waf_control"


# ---------------- API ----------------
@pytest.fixture
def api(world):
    sent, dep, store = [], world["dep"], world["store"]
    assert world["adm"].req("POST", "/sites", {**site("bank", "bank.localhost"), "owner_email": "own1@x.io"}).status_code == 201   # 'shop' (shop.example.com) comes from the base fixture
    ae = AlertEngine(store, lambda to, s, b: sent.append((to, s, b)))
    app = create_app(dep, "s" * 40, cookie_secure=False, probe=build_probe(dep, store, {}), alert_engine=ae)
    def login(email):
        c = C(app); assert c.login(email).status_code == 200; return c
    return {**world, "sent": sent, "login": login, "adm": login("admin@x.io")}

def test_api_policy_with_rate_limits_and_exclusions_is_stamped_and_audited(api):
    o = api["login"]("own1@x.io")
    r = o.req("PUT", "/sites/shop/policy", {"expected_version": 1, "rate_limits": [{"name": "login", "path": "/login", "per_minute": 10, "burst": 2}],
                                              "exclusions": [{"rule_id": "942100", "path": "/search", "reason": "search box holds SQL words", "created_by": "forged"}]})
    assert r.status_code == 200, r.get_json()
    pol = o.req("GET", "/sites/shop/policy").get_json()["config"]
    assert pol["rate_limits"][0]["per_minute"] == 10 and pol["exclusions"][0]["created_by"] == "own1@x.io"
    bad = o.req("PUT", "/sites/shop/policy", {"expected_version": 2, "exclusions": [{"rule_id": "942100", "reason": "no scope at all"}]})
    assert bad.status_code == 422 and "site-wide" in " ".join(bad.get_json()["details"])
    assert o.req("PUT", "/sites/bank/policy", {"expected_version": 1, "mode": "disabled"}).status_code == 200   # own1 owns bank too
    assert api["login"]("own2@x.io").req("PUT", "/sites/shop/policy", {"expected_version": 3}).status_code == 404

def test_api_scan_permissions_and_results(api):
    a, o = api["login"]("ana@x.io"), api["login"]("own1@x.io")
    assert a.req("POST", "/sites/shop/scan").status_code == 403
    r = o.req("POST", "/sites/shop/scan"); j = r.get_json(); assert r.status_code == 200 and j["summary"]["fail"] >= 1 and j["note"]
    assert a.req("GET", "/sites/shop/scan").get_json()["findings"]                   # analysts may read the result
    assert api["login"]("own2@x.io").req("GET", "/sites/shop/scan").status_code == 404

def test_api_alert_settings_test_email_and_history(api):
    o = api["login"]("own1@x.io")
    assert o.req("PUT", "/sites/shop/alerts", {"enabled": True}).status_code == 422
    assert o.req("POST", "/sites/shop/alerts/test").status_code == 422
    assert o.req("PUT", "/sites/shop/alerts", {"enabled": True, "email": "ops@example.com"}).status_code == 200
    r = o.req("POST", "/sites/shop/alerts/test").get_json(); assert r["sent"] is True and api["sent"][0][0] == "ops@example.com"
    h = o.req("GET", "/sites/shop/notifications").get_json(); assert h[0]["kind"] == "test" and h[0]["status"] == "sent"
    assert api["login"]("ana@x.io").req("PUT", "/sites/shop/alerts", {"enabled": False}).status_code == 403
    assert api["login"]("own2@x.io").req("GET", "/sites/shop/alerts").status_code == 404

def test_api_certificates_admin_only_then_https_policy_and_no_key_leak(api):
    o, adm = api["login"]("own1@x.io"), api["adm"]
    assert o.req("POST", "/sites/shop/tls", {"mode": "self_signed"}).status_code == 403
    assert o.req("PUT", "/sites/shop/policy", {"expected_version": 1, "https": "redirect"}).status_code == 422      # no certificate yet
    r = adm.req("POST", "/sites/shop/tls", {"mode": "self_signed"}); j = r.get_json()
    assert r.status_code == 200 and j["installed"] and j["self_signed"] and "privkey" not in json.dumps(j) and "PRIVATE" not in json.dumps(j)
    assert o.req("GET", "/sites/shop/tls").get_json()["installed"] is True
    assert o.req("PUT", "/sites/shop/policy", {"expected_version": 1, "https": "redirect", "hsts": True}).status_code == 200
    assert adm.req("POST", "/sites/shop/tls", {"certificate": "junk", "private_key": "junk"}).status_code == 422
    assert any(x["action"] == "tls.install" for x in api["store"].audit_list("shop"))

def test_api_coverage_view_and_admin_only_run(api):
    o = api["login"]("own1@x.io")
    assert len(o.req("GET", "/coverage").get_json()["categories"]) == 10 and o.req("POST", "/coverage/run").status_code == 403
    r = api["adm"].req("POST", "/coverage/run").get_json(); by = {c["id"]: c for c in r["categories"]}
    assert by["A05"]["verdict"] == "verified" and by["A01"]["verdict"] == "partial" and r["last_run"]["ts"]

def test_demo_sites_have_the_new_deliberate_flaws():
    import os, sys, tempfile
    os.environ.setdefault("CG_ORIGIN_LOG", tempfile.mkdtemp() + "/r.jsonl"); sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "origin"))
    import wsgi; from werkzeug.test import Client
    c = Client(wsgi.application)
    c.post("/login", data={"username": "alice", "password": "alice123"}, headers={"Host": "bank.localhost"})
    r = c.get("/report?id=abc", headers={"Host": "bank.localhost"}); assert r.status_code == 500 and "Traceback" in r.get_data(as_text=True)
    assert "repositoryformatversion" in c.get("/.git/config", headers={"Host": "shop.localhost"}).get_data(as_text=True)
