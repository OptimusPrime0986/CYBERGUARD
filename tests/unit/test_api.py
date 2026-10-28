import pytest
from werkzeug.security import generate_password_hash
from cyberguard.api import create_app
from .conftest import site

PW = "correct-horse-battery"


class C:
    """Tiny client wrapper that keeps the CSRF token like the dashboard does."""
    def __init__(self, app): self.c, self.csrf = app.test_client(), None
    def login(self, email, pw=PW):
        r = self.c.post("/api/v1/auth/login", json={"email": email, "password": pw})
        if r.status_code == 200: self.csrf = r.get_json()["csrf"]
        return r
    def req(self, m, url, json=None, csrf=True):
        h = {"X-CSRF-Token": self.csrf} if csrf and self.csrf else {}
        return self.c.open("/api/v1" + url, method=m, json=json, headers=h)


@pytest.fixture
def world(env):
    dep, eng, store, _ = env
    for email, role in [("admin@x.io", "admin"), ("own1@x.io", "owner"), ("own2@x.io", "owner"), ("ana@x.io", "analyst")]:
        store.create_user(email, generate_password_hash(PW), role)
    app = create_app(dep, "s" * 40, cookie_secure=False)
    adm = C(app); assert adm.login("admin@x.io").status_code == 200
    for sid, host in (("shop", "shop.example.com"), ("blog", "blog.example.com")):
        assert adm.req("POST", "/sites", {**site(sid, host), "owner_email": "own1@x.io" if sid == "shop" else "own2@x.io"}).status_code == 201
    store.grant("shop", store.get_user_by_email("ana@x.io")["id"])
    def login(email):
        c = C(app); assert c.login(email).status_code == 200; return c
    return dict(app=app, adm=adm, login=login, eng=eng, store=store, dep=dep)


def test_unauthenticated_blocked_everywhere(world):
    c = world["app"].test_client()
    for m, u in [("get", "/sites"), ("get", "/sites/shop"), ("put", "/sites/shop/protection"), ("get", "/users"), ("get", "/audit")]:
        assert getattr(c, m)("/api/v1" + u).status_code == 401
    assert c.get("/api/v1/health/live").status_code == 200

def test_login_generic_error_and_rate_limit(world):
    c = C(world["app"])
    a = c.login("nobody@x.io", "wrong"); b = c.login("own1@x.io", "wrong")
    assert a.status_code == b.status_code == 401 and a.get_json() == b.get_json()
    for _ in range(5): c.login("own1@x.io", "wrong")
    assert c.login("own1@x.io", PW).status_code == 429          # locked out per (ip,email); correct pw also refused

def test_csrf_required_for_state_changes(world):
    o = world["login"]("own1@x.io")
    r = o.req("PUT", "/sites/shop/protection", {"mode": "monitoring", "expected_version": 1}, csrf=False)
    assert r.status_code == 403 and r.get_json()["error"] == "csrf"

def test_owner_changes_own_site_and_state_is_verified(world):
    o = world["login"]("own1@x.io")
    r = o.req("PUT", "/sites/shop/protection", {"mode": "monitoring", "expected_version": 1})
    j = r.get_json(); assert r.status_code == 200 and j["effective_mode"] == "monitoring" and j["sync_state"] == "in_sync"
    s = o.req("GET", "/sites/shop").get_json()
    assert any("NOT blocked" in w for w in s["warnings"])

def test_cross_tenant_isolation(world):
    o1 = world["login"]("own1@x.io")
    for m, u, b in [("GET", "/sites/blog", None), ("PUT", "/sites/blog/protection", {"mode": "disabled", "expected_version": 1}),
                    ("GET", "/sites/blog/audit", None), ("GET", "/sites/blog/policy/versions", None), ("GET", "/sites/blog/health", None)]:
        assert o1.req(m, u, b).status_code == 404                # indistinguishable from nonexistent
    assert [s["site_id"] for s in o1.req("GET", "/sites").get_json()] == ["shop"]
    assert world["dep"].protection_state("blog")["effective_mode"] == "blocking"

def test_analyst_read_only_and_origin_hidden(world):
    a = world["login"]("ana@x.io")
    assert a.req("GET", "/sites/shop").status_code == 200
    assert "origin_host" not in a.req("GET", "/sites/shop").get_json()
    r = a.req("PUT", "/sites/shop/protection", {"mode": "disabled", "expected_version": 1})
    assert r.status_code == 403
    assert world["dep"].protection_state("shop")["effective_mode"] == "blocking"
    assert any(x["action"] == "authz.denied" for x in world["store"].audit_list())

def test_only_admin_manages_sites_and_users(world):
    o = world["login"]("own1@x.io")
    assert o.req("POST", "/sites", site("zzz", "z.example.com")).status_code == 403
    assert o.req("DELETE", "/sites/shop").status_code == 403
    assert o.req("GET", "/users").status_code == 403
    assert o.req("POST", "/users", {"email": "e@x.io", "password": PW, "role": "admin"}).status_code == 403

def test_failed_deployment_returns_502_and_keeps_policy(world):
    o = world["login"]("own1@x.io"); world["eng"].fail_validate = True
    r = o.req("PUT", "/sites/shop/protection", {"mode": "disabled", "expected_version": 1})
    j = r.get_json(); assert r.status_code == 502 and j["error"] == "deployment_failed"
    assert j["protection"]["effective_mode"] == "blocking" and j["protection"]["requested_mode"] == "disabled"

def test_conflict_validation_and_ssrf(world):
    o, a = world["login"]("own1@x.io"), world["adm"]
    assert o.req("PUT", "/sites/shop/protection", {"mode": "monitoring", "expected_version": 1}).status_code == 200
    assert o.req("PUT", "/sites/shop/protection", {"mode": "disabled", "expected_version": 1}).status_code == 409
    assert o.req("PUT", "/sites/shop/protection", {"mode": "pause", "expected_version": 2}).status_code == 422
    bad = a.req("POST", "/sites", {**site("evil", "evil.example.com"), "origin_host": "169.254.169.254"})
    assert bad.status_code == 422 and any("restricted" in d for d in bad.get_json()["details"])

def test_rollback_and_history(world):
    o = world["login"]("own1@x.io")
    o.req("PUT", "/sites/shop/protection", {"mode": "disabled", "expected_version": 1})
    r = o.req("POST", "/sites/shop/policy/rollback", {"to_version": 1, "expected_version": 2})
    assert r.status_code == 200 and r.get_json()["effective_mode"] == "blocking"
    assert [v["version"] for v in o.req("GET", "/sites/shop/policy/versions").get_json()] == [3, 2, 1]

def test_logout_revokes_session_server_side(world):
    o = world["login"]("own1@x.io"); cookie = o.c.get_cookie("session")
    assert o.req("POST", "/auth/logout").status_code == 200
    o.c.set_cookie("session", cookie.value)                      # replay the stolen cookie
    assert o.c.get("/api/v1/auth/me").status_code == 401

def test_create_user_validation_and_health(world):
    a = world["adm"]
    assert a.req("POST", "/users", {"email": "bad", "password": "short", "role": "root"}).status_code == 422
    assert a.req("POST", "/users", {"email": "new@x.io", "password": PW, "role": "analyst", "site_ids": ["shop"]}).status_code == 201
    assert a.req("GET", "/sites/shop/health").get_json()["status"] == "healthy"
    assert world["app"].test_client().get("/api/v1/health/ready").get_json()["status"] == "ready"


def test_serves_spa_and_keeps_api_separate(env, tmp_path):
    dep = env[0]; d = tmp_path / "dist"; (d / "assets").mkdir(parents=True)
    (d / "index.html").write_text("<html>app</html>"); (d / "assets" / "a.js").write_text("x")
    c = create_app(dep, "s" * 40, False, str(d)).test_client()
    assert b"app" in c.get("/").data and b"app" in c.get("/sites/anything").data       # SPA fallback
    assert c.get("/assets/a.js").data == b"x"
    assert c.get("/api/v1/nope").status_code in (404, 405) and c.get("/api/v1/sites").status_code == 401
    r = c.get("/"); assert r.headers["X-Frame-Options"] == "DENY" and "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_failed_new_site_registration_is_502_not_500(world):
    world["eng"].fail_validate = True                      # real-world trigger: nginx -t rejected the config
    r = world["adm"].req("POST", "/sites", site("fresh", "fresh.example.com"))
    j = r.get_json()
    assert r.status_code == 502 and j["error"] == "deployment_failed" and j["stage"] == "validation"
    assert "protection" not in j                           # site was never saved, so no state to report
    assert world["store"].get_site("fresh") is None


def test_site_modsec_file_has_no_duplicate_global_include(admin):
    from cyberguard.render import render_release
    from cyberguard.validation import Policy, validate_site
    from .conftest import site
    f = render_release(1, "/r", {"aa": (validate_site(site("aa"), admin), Policy(mode="monitoring"), 1)})
    assert "Include" not in f["modsec/aa.conf"] and "SecRuleEngine DetectionOnly" in f["modsec/aa.conf"]
