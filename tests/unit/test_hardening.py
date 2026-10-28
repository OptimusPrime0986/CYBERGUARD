import pytest
from cyberguard import tls
from cyberguard.deployer import DeploymentError
from cyberguard.render import render_release
from cyberguard.validation import AdminPolicy, Policy, ValidationError, validate_policy, validate_site
from .conftest import site

RL = {"name": "login", "path": "/login", "per_minute": 10, "burst": 3}
EX = {"rule_id": "942100", "path": "/search", "reason": "search box legitimately holds SQL words"}


def ent(admin, **pol):
    return {"aa": (validate_site(site("aa", "a.example.com"), admin), Policy(**pol), 4)}


# ---------- validation ----------
def test_defaults_and_old_policies_load():
    p = validate_policy(); assert (p.paranoia_level, p.anomaly_threshold, p.security_headers, p.generic_errors, p.https) == (1, 5, True, True, "off")
    assert Policy.from_dict({"mode": "monitoring", "max_body_bytes": 9, "allowed_methods": ["GET"]}).security_headers is True   # pre-upgrade row

@pytest.mark.parametrize("bad", [
    {"paranoia_level": 5}, {"paranoia_level": 0}, {"anomaly_threshold": 0}, {"anomaly_threshold": 101}, {"https": "always"}, {"hsts": True},
    {"rate_limits": [{"name": "a", "path": "login", "per_minute": 5}]}, {"rate_limits": [{"name": "a", "path": "/x", "per_minute": 0}]},
    {"rate_limits": [{"name": "A B", "path": "/x", "per_minute": 5}]}, {"rate_limits": [{**RL}, {**RL}]}, {"rate_limits": [{**RL, "name": f"r{i}"} for i in range(6)]},
    {"rate_limits": [{**RL, "path": "/a;b"}]}, {"rate_limits": [{**RL, "extra": 1}]},
    {"exclusions": [{"rule_id": "942100", "reason": "no scope given at all"}]},                         # site-wide needs admin permission
    {"exclusions": [{**EX, "rule_id": "949110"}]}, {"exclusions": [{**EX, "rule_id": "abc"}]}, {"exclusions": [{**EX, "target": "ARGS"}]},
    {"exclusions": [{**EX, "target": "ARGS:a;b"}]}, {"exclusions": [{**EX, "path": "/a b"}]}, {"exclusions": [{**EX, "reason": "no"}]},
    {"exclusions": [{**EX, "reason": "bad\nnewline here"}]}, {"exclusions": [{**EX, "expires": "tomorrow"}]}, {"exclusions": [EX] * 51},
    {"security_headers": "yes"}, {"inspect_responses": 1}])
def test_bad_new_fields_rejected(bad):
    with pytest.raises(ValidationError): validate_policy(bad)

def test_narrow_exclusions_ok_and_site_wide_only_with_admin_permission():
    assert validate_policy({"exclusions": [EX, {**EX, "path": None, "target": "ARGS:q"}]}).exclusions[1]["target"] == "ARGS:q"
    broad = {"exclusions": [{"rule_id": "942100", "reason": "legacy app needs this"}]}
    assert validate_policy(broad, AdminPolicy(allow_site_wide_exclusions=True))


# ---------- rendering ----------
def test_threshold_and_paranoia_rendered_per_site(admin):
    m = render_release(1, "/r", ent(admin, anomaly_threshold=8, paranoia_level=2))["modsec/aa.conf"]
    assert "inbound_anomaly_score_threshold=8" in m and "blocking_paranoia_level=2" in m and "detection_paranoia_level=2" in m and "Include" not in m

def test_exclusions_rendered_narrowly_with_unique_ids_and_expiry(admin):
    ex = ({**EX, "created_by": "a", "created_at": "x"}, {**EX, "path": None, "target": "ARGS:q", "rule_id": "941100"},
          {**EX, "rule_id": "930100", "expires": "2020-01-01"})
    m = render_release(1, "/r", ent(admin, exclusions=ex), today="2026-10-25")["modsec/aa.conf"]
    assert 'SecRule REQUEST_URI "@beginsWith /search" "id:1001000,phase:1,pass,nolog,ctl:ruleRemoveById=942100"' in m
    assert 'SecRule REQUEST_URI "@unconditionalMatch" "id:1001001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:q"' in m
    assert "930100" not in m                                     # expired exclusions are not applied
    assert "reason" not in m and "legitimately" not in m         # free text never reaches the engine config

def test_rate_limits_zones_locations_and_dry_run(admin):
    p = dict(rate_limits=(RL, {"name": "all", "path": "/", "per_minute": 600, "burst": 50}))
    f = render_release(1, "/r", ent(admin, **p))
    assert "zone=cg_aa_login:2m rate=10r/m;" in f["nginx/05-ratelimit.conf"] and "zone=cg_aa_all:2m rate=600r/m;" in f["nginx/05-ratelimit.conf"]
    c = f["nginx/10-site-aa.conf"]
    assert "location ^~ /login {" in c and "limit_req zone=cg_aa_login burst=3 nodelay;" in c and "limit_req_status 429;" in c
    assert "limit_req zone=cg_aa_all burst=50 nodelay;" in c.split("location / {")[1] and "Retry-After 60" in c and "limit_req_dry_run" not in c
    assert "limit_req_dry_run on;" in render_release(1, "/r", ent(admin, mode="monitoring", **p))["nginx/10-site-aa.conf"]
    assert "limit_req zone=cg_aa_login" in render_release(1, "/r", ent(admin, mode="disabled", **p))["nginx/10-site-aa.conf"]   # infra control survives 'disabled'

def test_headers_banner_and_error_pages(admin):
    f = render_release(1, "/r", ent(admin)); c = f["nginx/10-site-aa.conf"]
    assert "server_tokens off;" not in f["nginx/00-default.conf"]      # the image already sets it; a second one fails nginx -t (seen on a real run)
    for h in ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"): assert f'add_header {h} ' in c and f"proxy_hide_header {h};" in c
    assert "proxy_hide_header X-Powered-By;" in c and "proxy_intercept_errors on;" in c and "location @cg_e500" in c and "error_page 502 @cg_e502;" in c
    off = render_release(1, "/r", ent(admin, security_headers=False, generic_errors=False))["nginx/10-site-aa.conf"]
    assert "add_header X-Frame" not in off and "proxy_intercept_errors" not in off and "@cg_e500" not in off

def test_response_inspection_toggle(admin):
    assert "SecResponseBodyAccess Off" in render_release(1, "/r", ent(admin))["modsec/aa.conf"]
    assert "SecResponseBodyAccess On" in render_release(1, "/r", ent(admin, inspect_responses=True))["modsec/aa.conf"]

def test_https_listener_redirect_hsts_and_default_server(admin):
    f = render_release(1, "/etc/cyberguard", ent(admin, https="redirect", hsts=True), tls_sites={"aa"}, https_port=8443); c = f["nginx/10-site-aa.conf"]
    assert "listen 8443 ssl;" in c and "ssl_certificate /etc/cyberguard/tls/aa/fullchain.pem;" in c and "ssl_protocols TLSv1.2 TLSv1.3;" in c and "ssl_session_tickets off;" in c
    assert "return 301 https://$host:8443$request_uri;" in c.split("listen 8443 ssl;")[0]
    assert c.count("Strict-Transport-Security") == 1 and c.index("Strict-Transport-Security") > c.index("listen 8443 ssl;")   # HSTS only on the TLS listener
    assert "listen 8443 ssl default_server;" in f["nginx/00-default.conf"]
    assert '"https": "redirect"' in f["manifest.json"]
    opt = render_release(1, "/r", ent(admin, https="optional"), tls_sites={"aa"})["nginx/10-site-aa.conf"]
    assert "return 301" not in opt and "proxy_pass" in opt.split("listen 8443 ssl;")[0]
    assert "listen 8443" not in render_release(1, "/r", ent(admin, https="redirect"))["nginx/10-site-aa.conf"]            # no cert installed -> no TLS server

def test_trusted_proxies_only_when_configured(admin):
    assert "set_real_ip_from" not in render_release(1, "/r", ent(admin))["nginx/10-site-aa.conf"]
    c = render_release(1, "/r", ent(admin), trusted_proxies=("10.1.0.0/16",))["nginx/10-site-aa.conf"]
    assert "set_real_ip_from 10.1.0.0/16;" in c and "real_ip_header X-Forwarded-For;" in c and "real_ip_recursive on;" in c


# ---------- deployer ----------
def reg(dep, **pol): return dep.register_site("alice", site("shop", "shop.example.com"), pol or {"mode": "blocking"})

def test_exclusion_stamped_by_server_and_preserved(env):
    dep, eng, store, _ = env; reg(dep)
    forged = {**EX, "created_by": "someone-else", "created_at": "1999-01-01"}
    dep.set_policy("mallory", "shop", {"exclusions": [forged]}, 1)
    e = store.get_policy("shop", 2)["config"]["exclusions"][0]
    assert e["created_by"] == "mallory" and e["created_at"].startswith("20") and e["created_at"] != "1999-01-01"
    dep.set_policy("bob", "shop", {"exclusions": [EX, {**EX, "path": "/other"}]}, 2)
    ex = store.get_policy("shop", 3)["config"]["exclusions"]
    assert ex[0]["created_by"] == "mallory" and ex[1]["created_by"] == "bob"              # untouched entry keeps its original author

def test_https_requires_installed_certificate(env):
    dep, *_ = env; reg(dep)
    with pytest.raises(ValidationError) as e: dep.set_policy("a", "shop", {"https": "redirect"}, 1)
    assert "certificate" in str(e.value)
    cert, key = tls.self_signed(["shop.example.com"]); tls.install(dep.root, "shop", cert, key)
    assert dep.set_policy("a", "shop", {"https": "optional"}, 1)["effective_version"] == 2
    assert '"https": "optional"' in (dep.root / "active" / "manifest.json").read_text()
    assert "listen 8443 ssl;" in (dep.root / "active" / "nginx" / "10-site-shop.conf").read_text()

def test_expire_exclusions_removes_only_expired_through_a_verified_change(env):
    dep, eng, store, _ = env; reg(dep)
    dep.set_policy("a", "shop", {"exclusions": [{**EX, "expires": "2020-01-01"}, {**EX, "path": "/keep", "expires": "2099-01-01"}]}, 1)
    assert dep.expire_exclusions() == ["shop"]
    left = store.get_policy("shop", store.get_state("shop")["effective_version"])["config"]["exclusions"]
    assert [e["path"] for e in left] == ["/keep"] and dep.expire_exclusions() == []

def test_new_settings_flow_through_a_failed_deploy_safely(env):
    dep, eng, store, _ = env; reg(dep); eng.fail_validate = True
    with pytest.raises(DeploymentError): dep.set_policy("a", "shop", {"rate_limits": [RL], "anomaly_threshold": 2}, 1)
    assert dep.protection_state("shop")["effective_version"] == 1 and store.get_policy("shop", 1)["config"]["anomaly_threshold"] == 5


# ---------- certificates ----------
def test_certificate_validation(tmp_path):
    cert, key = tls.self_signed(["shop.example.com", "www.shop.example.com"])
    info = tls.inspect(cert, key, ["shop.example.com"]); assert info["self_signed"] and "www.shop.example.com" in info["san"]
    other_cert, other_key = tls.self_signed(["shop.example.com"])
    for c, k, why in ((cert, other_key, "does not match"), ("junk", key, "valid PEM"), (cert, "junk", "valid unencrypted"), (cert, key, None)):
        if why is None:
            with pytest.raises(ValidationError) as e: tls.inspect(cert, key, ["other.example.org"]); assert "does not cover" in str(e.value)
        else:
            with pytest.raises(ValidationError) as e: tls.inspect(c, k, ["shop.example.com"]); assert why in str(e.value)
    tls.install(tmp_path, "shop", cert, key); st = tls.status(tmp_path, "shop")
    assert st["installed"] and st["days_left"] >= 89 and oct((tmp_path / "tls/shop/privkey.pem").stat().st_mode & 0o777) == "0o600"
    assert tls.status(tmp_path, "none")["installed"] is False
