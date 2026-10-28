"""Baseline: the training sites really ARE vulnerable when no firewall is in front (otherwise the demo proves nothing)."""
import os, sys, tempfile
os.environ["CG_ORIGIN_LOG"] = tempfile.mkdtemp() + "/r.jsonl"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "origin"))
import pytest
import wsgi, bank, shop
from werkzeug.test import Client


def cl(host): return Client(wsgi.application)
def get(c, host, path, **kw): return c.get(path, headers={"Host": host}, **kw)
def post(c, host, path, data): return c.post(path, data=data, headers={"Host": host})
def txt(r): return r.get_data(as_text=True)


@pytest.fixture(autouse=True)
def fresh():
    bank.seed(); shop.seed()


def login(c, u="alice", p="alice123", host="bank.localhost"): return post(c, host, "/login", {"username": u, "password": p})


def test_dispatch_by_host():
    c = Client(wsgi.application)
    assert "ZenithBank" in txt(get(c, "bank.localhost:8000", "/")) and "ShopEasy" in txt(get(c, "shop.localhost", "/"))
    assert get(c, "demo.localhost", "/").get_json()["reached_origin"] is True       # original site / Phase 1 tests unaffected


def test_bank_normal_login_and_wrong_password():
    c = Client(wsgi.application)
    assert login(c).status_code == 302 and "Alice Morgan" in txt(get(c, "bank.localhost", "/dashboard", follow_redirects=True))
    assert "Invalid" in txt(login(Client(wsgi.application), p="wrong"))


def test_bank_sqli_login_bypass_and_error_leak():
    c = Client(wsgi.application)
    assert login(c, "admin'--", "x").status_code == 302                              # signed in as admin without the password
    assert "Bank Administrator" in txt(get(c, "bank.localhost", "/dashboard"))
    leak = txt(login(Client(wsgi.application), "'", "x"))
    assert "Database error" in leak and "SELECT id, username" in leak


def test_bank_union_injection_steals_credentials():
    c = Client(wsgi.application); login(c)
    t = txt(get(c, "bank.localhost", "/transactions", query_string={"q": "' UNION SELECT username,password,0 FROM users--"}))
    assert "Adm1n!demo" in t and "bob12345" in t


def test_bank_reflected_and_stored_xss_are_unescaped():
    c = Client(wsgi.application); login(c)
    assert "<script>alert(1)</script>" in txt(get(c, "bank.localhost", "/transactions", query_string={"q": "<script>alert(1)</script>"}))
    post(c, "bank.localhost", "/feedback", {"name": "x", "message": "<img src=x onerror=alert(1)>"})
    assert "<img src=x onerror=alert(1)>" in txt(get(c, "bank.localhost", "/feedback"))


def test_bank_path_traversal_reads_fake_files_only():
    c = Client(wsgi.application); login(c)
    t = txt(get(c, "bank.localhost", "/statement", query_string={"file": "../../../etc/passwd"}))
    assert "FAKE-root" in t
    assert "No such" in txt(get(c, "bank.localhost", "/statement", query_string={"file": "../../../../proc/self/environ"}))   # cannot reach real files


def test_bank_idor_and_negative_transfer_work_which_a_waf_cannot_stop():
    c = Client(wsgi.application); login(c)
    assert "Bob Carter" in txt(get(c, "bank.localhost", "/account", query_string={"id": 3}))
    assert "Transferred" in txt(post(c, "bank.localhost", "/transfer", {"from_id": 3, "to_number": "ZB-1001-0001", "amount": "-500", "memo": "m"}))


def test_shop_vulnerabilities():
    c = Client(wsgi.application)
    assert "Sh0p!demo" in txt(get(c, "shop.localhost", "/search", query_string={"q": "' UNION SELECT id,username,password,role FROM users--"}))
    assert "carol123" in txt(get(c, "shop.localhost", "/product", query_string={"id": "0 UNION SELECT 1,username,0,password,role FROM users"}))
    assert "<script>x</script>" in txt(get(c, "shop.localhost", "/search", query_string={"q": "<script>x</script>"}))
    assert login(c, "shopadmin'--", "x", "shop.localhost").status_code == 302
    post(c, "shop.localhost", "/review", {"pid": 1, "author": "a", "body": "<img src=x onerror=alert(1)>"})
    assert "<img src=x onerror=alert(1)>" in txt(get(c, "shop.localhost", "/product", query_string={"id": 1}))
    c2 = Client(wsgi.application); login(c2, "carol", "carol123", "shop.localhost")
    assert "99 Sample Road" in txt(get(c2, "shop.localhost", "/order", query_string={"id": 2}))            # dave's order


def test_requests_that_reach_the_sites_are_logged_and_reset_works():
    c = Client(wsgi.application); get(c, "bank.localhost", "/", ); n = len(open(os.environ["CG_ORIGIN_LOG"]).read().splitlines())
    assert n >= 1
    login(c); post(c, "bank.localhost", "/feedback", {"name": "x", "message": "hi"}); post(c, "bank.localhost", "/__reset", {})
    assert "hi" not in txt(get(c, "bank.localhost", "/feedback"))


def test_attack_guides_render():
    c = Client(wsgi.application)
    for h in ("bank.localhost", "shop.localhost"):
        t = txt(get(c, h, "/attack-guide")); assert "NOT blocked" in t and "TRAINING SITE" in t
