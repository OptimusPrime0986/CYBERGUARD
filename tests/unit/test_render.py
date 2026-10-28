import json
from cyberguard.render import render_release
from cyberguard.validation import Policy, validate_site
from .conftest import site

def ents(admin, modes):
    return {sid: (validate_site(site(sid, f"{sid}.example.com"), admin), Policy(mode=m), 1) for sid, m in modes.items()}

def test_modes_render_correct_engine_directives(admin):
    f = render_release(1, "/etc/cyberguard", ents(admin, {"aa": "blocking", "bb": "monitoring", "cc": "disabled"}))
    assert "SecRuleEngine On" in f["modsec/aa.conf"]
    assert "SecRuleEngine DetectionOnly" in f["modsec/bb.conf"]
    assert "modsec/cc.conf" not in f                       # disabled: no rules file at all
    assert "modsecurity off;" in f["nginx/10-site-cc.conf"] and "modsecurity on;" in f["nginx/10-site-aa.conf"]
    assert "proxy_pass" in f["nginx/10-site-cc.conf"]       # routing path preserved when disabled
    assert "return 444" in f["nginx/00-default.conf"]       # unknown Host is dropped

def test_isolation_changing_one_site_leaves_others_byte_identical(admin):
    a = render_release(1, "/r", ents(admin, {"aa": "blocking", "bb": "blocking"}))
    b = render_release(1, "/r", ents(admin, {"aa": "disabled", "bb": "blocking"}))
    assert a["nginx/10-site-bb.conf"] == b["nginx/10-site-bb.conf"]
    assert a["modsec/bb.conf"] == b["modsec/bb.conf"]
    assert a["nginx/10-site-aa.conf"] != b["nginx/10-site-aa.conf"]

def test_deterministic_and_manifest(admin):
    e = ents(admin, {"aa": "blocking"})
    assert render_release(3, "/r", e) == render_release(3, "/r", e)
    m = json.loads(render_release(3, "/r", e)["manifest.json"])
    assert m["release"] == 3 and m["sites"]["aa"]["mode"] == "blocking"

def test_https_origin_verifies_by_default_and_overwrites_xff(admin):
    s = validate_site({**site("aa"), "origin_scheme": "https", "origin_port": 443}, admin)
    conf = render_release(1, "/r", {"aa": (s, Policy(), 1)})["nginx/10-site-aa.conf"]
    assert "proxy_ssl_verify on;" in conf and "X-Forwarded-For $remote_addr" in conf
    assert "$proxy_add_x_forwarded_for" not in conf
