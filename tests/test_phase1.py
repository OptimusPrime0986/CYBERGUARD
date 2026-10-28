"""Phase 1 acceptance tests: real HTTP through NGINX + ModSecurity + CRS.

A block only counts when ALL hold (spec 18.2): proxy returned 403, the ModSecurity audit log has a
matching entry with expected rule IDs, and the origin's own log has NO record of the request.
"""
import json, os, re, subprocess, time, uuid
import pytest
import requests

PORTS = {"blocking": int(os.getenv("PORT_BLOCKING", 8081)), "detect": int(os.getenv("PORT_DETECT", 8082)),
         "off": int(os.getenv("PORT_OFF", 8083))}
SERVICE = {"blocking": "proxy-blocking", "detect": "proxy-detect", "off": "proxy-off"}
AUDIT_LOG = os.getenv("MODSEC_AUDIT_LOG_PATH", "/var/log/modsec_audit.log")  # verify against your image


def dc_exec(service, *cmd):
    r = subprocess.run(["docker", "compose", "exec", "-T", service, *cmd], capture_output=True, text=True, timeout=30)
    return r.stdout if r.returncode == 0 else ""


def origin_hits(test_id):
    hits = []
    for line in dc_exec("origin", "cat", "/data/requests.jsonl").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("test_id") == test_id:
            hits.append(e)
    return hits


def audit_rule_ids(mode, test_id, wait=6.0):
    deadline, ids = time.time() + wait, set()
    while time.time() < deadline:
        for line in dc_exec(SERVICE[mode], "cat", AUDIT_LOG).splitlines():
            if test_id in line:
                ids |= set(re.findall(r'"ruleId"\s*:\s*"?(\d+)', line))
        if ids:
            return ids
        time.sleep(0.5)
    return ids


def send(mode, method="GET", path="/", **kw):
    tid = uuid.uuid4().hex
    headers = kw.pop("headers", {}); headers["X-Test-Id"] = tid
    r = requests.request(method, f"http://127.0.0.1:{PORTS[mode]}{path}", headers=headers, timeout=10,
                         allow_redirects=False, **kw)
    return tid, r


@pytest.fixture(scope="session", autouse=True)
def stack_ready():
    deadline, pending = time.time() + 90, set(PORTS)
    while pending and time.time() < deadline:
        for m in list(pending):
            try:
                requests.get(f"http://127.0.0.1:{PORTS[m]}/", timeout=2); pending.discard(m)
            except requests.RequestException:
                pass
        time.sleep(1)
    assert not pending, f"proxies not reachable: {pending}"


ATTACKS = {
    "sqli_union": dict(path="/search", params={"q": "1 UNION SELECT username,password FROM users--"}, family="942"),
    "sqli_tautology": dict(path="/search", params={"q": "' OR '1'='1"}, family="942"),
    "xss_script": dict(path="/comment", params={"text": "<script>alert(1)</script>"}, family="941"),
    "traversal": dict(path="/download", params={"file": "../../../../etc/passwd"}, family="930"),
    "cmdi": dict(path="/ping", params={"host": "127.0.0.1;cat /etc/passwd"}, family="932"),
}
BENIGN = {
    "plain": dict(path="/", params={}),
    "search_words": dict(path="/search", params={"q": "how to select a good union rep"}),
    "html_prose": dict(path="/comment", params={"text": "I love the <b> tag, it is bold."}),
    "unicode": dict(path="/search", params={"q": "café 東京 пример"}),
    "encoded_space": dict(path="/search", params={"q": "100% sure & more"}),
}


@pytest.mark.parametrize("name", ATTACKS)
def test_blocking_mode_blocks_and_origin_never_sees_it(name):
    a = ATTACKS[name]
    tid, r = send("blocking", path=a["path"], params=a["params"])
    ids = audit_rule_ids("blocking", tid)
    assert r.status_code == 403, f"expected 403, got {r.status_code}"
    assert any(i.startswith(a["family"]) for i in ids), f"no {a['family']}xxx rule in {ids}"
    assert "949110" in ids, f"anomaly-threshold rule did not fire: {ids}"
    assert origin_hits(tid) == [], "BLOCKED request reached the origin"


@pytest.mark.parametrize("name", ATTACKS)
def test_detect_mode_detects_but_forwards(name):
    a = ATTACKS[name]
    tid, r = send("detect", path=a["path"], params=a["params"])
    ids = audit_rule_ids("detect", tid)
    assert any(i.startswith(a["family"]) for i in ids), f"no {a['family']}xxx rule in {ids}"
    assert r.status_code == 200
    assert len(origin_hits(tid)) == 1


@pytest.mark.parametrize("name", ATTACKS)
def test_off_mode_forwards_without_detection(name):
    a = ATTACKS[name]
    tid, r = send("off", path=a["path"], params=a["params"])
    assert r.status_code == 200 and len(origin_hits(tid)) == 1
    assert audit_rule_ids("off", tid, wait=2.0) == set()


@pytest.mark.parametrize("mode", ["blocking", "detect", "off"])
@pytest.mark.parametrize("name", BENIGN)
def test_benign_requests_pass_in_every_mode(mode, name):
    b = BENIGN[name]
    tid, r = send(mode, path=b["path"], params=b["params"])
    assert r.status_code == 200, f"false positive in {mode}: {r.status_code}"
    assert len(origin_hits(tid)) == 1


def test_benign_post_json_passes_in_blocking():
    tid, r = send("blocking", "POST", "/api/items", json={"name": "widget", "note": "select one"})
    assert r.status_code == 200 and len(origin_hits(tid)) == 1


def test_origin_has_no_published_port():
    r = subprocess.run(["docker", "compose", "port", "origin", "5000"], capture_output=True, text=True)
    assert r.stdout.strip() == "", f"origin port is published: {r.stdout}"


def test_backend_network_is_internal():
    names = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True).stdout.split()
    net = next((n for n in names if n.endswith("_backend")), None)
    assert net, "backend network not found"
    info = json.loads(subprocess.run(["docker", "network", "inspect", net], capture_output=True, text=True).stdout)
    assert info[0]["Internal"] is True
