import json
from datetime import datetime, timezone
import pytest
from werkzeug.security import generate_password_hash
from cyberguard import events as ev
from cyberguard.api import create_app
from .conftest import site
from .test_api import C, PW

NOW = datetime.now(timezone.utc)
ISO = NOW.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def audit(tid, host="shop.example.com", uri="/search?q=%27+OR+1%3D1--&password=hunter2", code=403, rules=None, extra=None):
    rules = rules or [("942100", 2, "SQL Injection Attack Detected via libinjection", ["attack-sqli"]),
                      ("949110", 2, "Inbound Anomaly Score Exceeded (Total Score: 5)", ["anomaly-evaluation"])]
    t = {"unique_id": tid, "client_ip": "203.0.113.9", "time_stamp": NOW.strftime("%a %b %d %H:%M:%S %Y"),
         "request": {"method": "GET", "uri": uri, "headers": {"Host": host, "User-Agent": "curl/8\x07evil\nINJECT"}},
         "response": {"http_code": code},
         "messages": [{"message": m, "details": {"ruleId": r, "severity": str(s), "tags": tg, "data": "Matched Data: ' OR 1=1--"}} for r, s, m, tg in rules]}
    t.update(extra or {})
    return json.dumps({"transaction": t})


def access(rid, host="shop.example.com", status=403, up="-", uri="/search", ver=2, mode="blocking", rt="0.004"):
    return json.dumps({"t": ISO, "host": host, "site": "shop", "ver": str(ver), "mode": mode, "rid": rid, "method": "GET", "uri": uri, "status": status, "up": up, "rt": rt, "ip": "203.0.113.9"})


@pytest.fixture
def pipe(env, tmp_path):
    dep, eng, store, _ = env
    dep.register_site("a", site("shop", "shop.example.com"), {"mode": "blocking"})
    d = tmp_path / "logs"; d.mkdir()
    return store, ev.Ingestor(store, d), d


def w(d, name, *lines, raw=None):
    with open(d / f"{name}.jsonl", "a") as f: f.write(raw if raw is not None else "".join(l + "\n" for l in lines))


def test_blocked_event_normalised_redacted_and_versioned(pipe):
    store, ing, d = pipe
    w(d, "access", access("r1")); w(d, "audit", audit("r1")); ing.run_once()
    e = ev.list_events(store, "shop", {})["items"][0]
    assert (e["event_type"], e["rule_id"], e["severity"], e["category"], e["score"]) == ("blocked", "942100", "critical", "sqli", 5)
    assert "949110" not in e["rule_ids"]                           # meta rule is not reported as an attack rule
    assert "hunter2" not in e["query"] and "password=[redacted]" in e["query"]
    assert "\x07" not in e["user_agent"] and "\n" not in e["user_agent"]   # log-injection control chars neutralised
    assert (e["policy_version"], e["mode"]) == (2, "blocking")      # exact version joined from the access log


def test_detection_only_is_separate_from_blocked(pipe):
    store, ing, d = pipe
    w(d, "audit", audit("r2", code=200)); ing.run_once()
    e = ev.get_event(store, "shop", "r2")
    assert e["event_type"] == "detected" and e["status"] == 200 and e["policy_version"] is None   # unknown stays unknown


def test_traffic_counts_come_only_from_access_log(pipe):
    store, ing, d = pipe
    w(d, "access", access("a1", status=200, up="200"), access("a2", status=200, up="200"), access("a3"), access("a4", status=405),
      access("a5", host="unknown.example.org", status=200, up="200"), access("c1", uri="/__cg_canary"))
    ing.run_once()
    t = ev.traffic(store, ["shop"], "15m")["totals"]
    assert (t["total"], t["allowed"], t["blocked"], t["rejected"]) == (4, 2, 1, 1)    # unknown host + canary excluded
    assert t["avg_latency_ms"] == 4.0
    assert sum(b["blocked"] for b in ev.traffic(store, ["shop"], "15m")["series"]) == 1


def test_403_from_origin_is_not_counted_as_waf_block(pipe):
    store, ing, d = pipe
    w(d, "access", access("o1", status=403, up="403")); ing.run_once()
    assert ev.traffic(store, ["shop"], "15m")["totals"]["blocked"] == 0


def test_restart_does_not_double_count_and_events_dedupe(pipe):
    store, ing, d = pipe
    w(d, "access", access("a1")); w(d, "audit", audit("e1")); ing.run_once(); ing.run_once()
    ev.Ingestor(store, d).run_once()                                # "restart": new ingestor, offsets come from the DB
    assert ev.traffic(store, ["shop"], "15m")["totals"]["total"] == 1
    w(d, "audit", audit("e1")); ing.run_once()                      # same transaction delivered twice
    assert ev.list_events(store, "shop", {})["total"] == 1


def test_partial_line_waits_and_malformed_lines_are_counted_not_fatal(pipe):
    store, ing, d = pipe
    line = audit("p1"); w(d, "audit", raw=line[:40]); ing.run_once()
    assert ev.list_events(store, "shop", {})["total"] == 0
    w(d, "audit", raw=line[40:] + "\nnot json\n"); ing.run_once()
    assert ev.list_events(store, "shop", {})["total"] == 1
    assert ev.pipeline_status(store)["malformed_lines"] == 1


def test_rotation_resets_offset(pipe):
    store, ing, d = pipe
    w(d, "access", *[access(f"x{i}") for i in range(5)]); ing.run_once()
    (d / "access.jsonl").write_text(access("y1") + "\n"); ing.run_once()    # file shrank => rotated
    assert ev.traffic(store, ["shop"], "15m")["totals"]["total"] == 6


def test_filters_pagination_and_wildcard_safety(pipe):
    store, ing, d = pipe
    w(d, "audit", *[audit(f"e{i}", uri=f"/s{i}?q=x") for i in range(30)],
      audit("xss1", uri="/c?t=%3Cscript%3E", rules=[("941100", 2, "XSS Attack Detected via libinjection", ["attack-xss"]), ("949110", 2, "Inbound Anomaly Score Exceeded (Total Score: 5)", [])]),
      audit("low1", code=200, rules=[("920350", 4, "Host header is a numeric IP address", ["attack-protocol"])]))
    ing.run_once()
    assert ev.list_events(store, "shop", {})["total"] == 32
    assert len(ev.list_events(store, "shop", {}, limit=10, offset=30)["items"]) == 2
    assert ev.list_events(store, "shop", {"rule_id": "941100"})["total"] == 1
    assert ev.list_events(store, "shop", {"severity": "medium", "type": "detected"})["total"] == 1
    assert ev.list_events(store, "shop", {"q": "s_"})["total"] == 0                   # '_' is literal, not a single-char wildcard
    assert ev.list_events(store, "shop", {"q": "%27"})["total"] == 1                  # % is literal too (only the one encoded query matches)
    assert ev.list_events(store, "shop", {"q": "s1"})["total"] == 11
    sec = ev.security(store, ["shop"], "15m")
    assert sec["by_type"] == {"blocked": 31, "detected": 1} and {c["label"] for c in sec["by_category"]} >= {"sqli", "xss", "protocol"}
    assert sec["top_rules"][0]["rule_id"] == "942100"


def test_api_events_respect_ownership_and_roles(env, tmp_path):
    dep, eng, store, _ = env
    for email, role in [("admin@x.io", "admin"), ("o1@x.io", "owner"), ("o2@x.io", "owner")]:
        store.create_user(email, generate_password_hash(PW), role)
    app = create_app(dep, "s" * 40, cookie_secure=False)
    adm = C(app); adm.login("admin@x.io")
    for sid, h, o in (("shop", "shop.example.com", "o1@x.io"), ("blog", "blog.example.com", "o2@x.io")):
        assert adm.req("POST", "/sites", {**site(sid, h), "owner_email": o}).status_code == 201
    d = tmp_path / "logs"; d.mkdir(); ing = ev.Ingestor(store, d)
    w(d, "audit", audit("s1"), audit("b1", host="blog.example.com")); w(d, "access", access("s1"), access("b1", host="blog.example.com")); ing.run_once()
    o1 = C(app); o1.login("o1@x.io")
    r = o1.req("GET", "/sites/shop/events"); assert r.status_code == 200 and r.get_json()["total"] == 1
    assert o1.req("GET", "/sites/blog/events").status_code == 404 and o1.req("GET", "/sites/blog/events/b1").status_code == 404
    assert o1.req("GET", "/sites/shop/events/b1").status_code == 404                  # event id from another site
    ov = o1.req("GET", "/analytics/overview?range=15m").get_json()
    assert ov["traffic"]["totals"]["total"] == 1 and [p["site_id"] for p in ov["per_site"]] == ["shop"] and ov["pipeline"]["status"] == "ok"
    assert adm.req("GET", "/analytics/overview?range=15m").get_json()["traffic"]["totals"]["total"] == 2
    assert o1.req("GET", "/analytics/overview?range=99y").status_code == 422
    assert app.test_client().get("/api/v1/analytics/overview").status_code == 401


def test_pipeline_status_waiting_before_any_logs(env):
    assert ev.pipeline_status(env[2])["status"] == "waiting"
