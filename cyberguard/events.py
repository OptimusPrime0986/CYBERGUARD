"""WAF event pipeline.

The proxy-side agent copies two log files into the shared volume:
  audit.jsonl  - ModSecurity JSON audit log (one transaction per line, only transactions with rule matches / 4xx / 5xx)
  access.jsonl - NGINX access log in JSON (every request: host, status, upstream status, latency, policy version)
This module tails them, normalises, redacts, de-duplicates and stores them, and answers dashboard queries.
Every number shown in the dashboard is derived from these logs; nothing is synthesised.

Guarantees: each batch commits its rows and the new file offset in ONE transaction (no double counting on restart);
events are keyed by transaction id (INSERT OR IGNORE). NOT guaranteed: delivery if the proxy host dies before the
agent copies a line, or lines lost when a shipped file is rotated (see README).
"""
import collections, hashlib, json, re, threading, time, urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

META = {"949110", "959100", "980130", "980140", "980170"}       # CRS evaluation/correlation rules, not attacks themselves
BLOCK_EVAL = {"949110", "959100"}
SENSITIVE = re.compile(r"pass|pwd|token|secret|auth|key|card|cvv|ssn|session", re.I)
CTRL = re.compile(r"[\x00-\x1f\x7f]")
SEV_NAME = {0: "critical", 1: "critical", 2: "critical", 3: "high", 4: "medium", 5: "low", 6: "informational", 7: "informational"}
SEV_ORDER = ["critical", "high", "medium", "low", "informational"]
RANGES = {"15m": (15, 1), "1h": (60, 5), "24h": (1440, 60), "7d": (10080, 360)}   # minutes covered, bucket minutes
CANARY = "/__cg_canary"


def _clean(s, n):
    return CTRL.sub(" ", str("" if s is None else s))[:n]


def redact_query(q):
    out = []
    for part in q.split("&"):
        k, _, v = part.partition("=")
        out.append(f"{k}=[redacted]" if v and SENSITIVE.search(urllib.parse.unquote_plus(k)) else part)
    return "&".join(out)


def _h(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v if isinstance(v, str) else (v[0] if v else "")
    return ""


def _utc(ts):
    for fmt in ("%a %b %d %H:%M:%S %Y",):
        try: return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError): pass
    try:
        d = datetime.fromisoformat(ts)
        return d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def parse_audit(line):
    """-> normalised event dict, or None when the transaction matched no rule (plain 4xx/5xx)."""
    try:
        t = json.loads(line)["transaction"]
    except (ValueError, KeyError, TypeError):
        raise ValueError("unparseable audit line")
    rules = []
    for m in t.get("messages") or []:
        d = m.get("details") or {}
        sev = d.get("severity")
        rules.append({"id": str(d.get("ruleId", "")), "msg": _clean(m.get("message", ""), 200),
                      "sev": int(sev) if str(sev).isdigit() else None, "tags": d.get("tags") or [], "data": _clean(d.get("data", ""), 120)})
    if not rules:
        return None
    req, resp = t.get("request") or {}, t.get("response") or {}
    uri = req.get("uri") or ""
    sp = urllib.parse.urlsplit(uri)
    if sp.path == CANARY:
        return None
    code = resp.get("http_code")
    blocked = code == 403 and any(r["id"] in BLOCK_EVAL for r in rules)
    real = [r for r in rules if r["id"] not in META] or rules
    primary = min(real, key=lambda r: 9 if r["sev"] is None else r["sev"])
    score = next((int(m.group(1)) for r in rules if r["id"] == "949110" for m in [re.search(r"Total Score: (\d+)", r["msg"])] if m), None)
    cat = next((x[7:] for r in real for x in r["tags"] if isinstance(x, str) and x.startswith("attack-")), "other")
    headers = req.get("headers") or {}
    eid = t.get("unique_id") or t.get("id") or hashlib.sha1(line.encode()).hexdigest()
    return {"id": _clean(eid, 64), "ts": _utc(t.get("time_stamp")).isoformat(), "host": _h(headers, "host").split(":")[0].lower(),
            "event_type": "blocked" if blocked else "detected", "rule_id": primary["id"], "rule_ids": [r["id"] for r in real],
            "message": primary["msg"], "severity": SEV_NAME.get(primary["sev"], "informational"), "category": _clean(cat, 30),
            "score": score, "method": _clean(req.get("method"), 10), "path": _clean(sp.path, 300), "query": _clean(redact_query(sp.query), 300),
            "status": code, "client_ip": _clean(t.get("client_ip"), 45), "user_agent": _clean(_h(headers, "user-agent"), 150),
            "data": primary["data"]}


def parse_access(line):
    try:
        r = json.loads(line)
        d = _utc(r["t"])
        return {"minute": d.strftime("%Y-%m-%dT%H:%M"), "host": str(r.get("host", "")).lower(), "status": int(r["status"]),
                "up": str(r.get("up", "-")), "rt": float(r.get("rt") or 0), "rid": str(r.get("rid", "")), "uri": str(r.get("uri", "")),
                "ver": int(r["ver"]) if str(r.get("ver", "")).isdigit() and int(r["ver"]) > 0 else None, "mode": str(r.get("mode", ""))}
    except (ValueError, KeyError, TypeError):
        raise ValueError("unparseable access line")


class Ingestor:
    def __init__(self, store, log_dir, interval=2.0, retention_days=30):
        self.store, self.dir, self.interval, self.retention = store, Path(log_dir), interval, retention_days
        self.ctx = collections.OrderedDict()             # request id -> (policy version, mode); lets events carry the exact policy version
        self._purged, self._stop, self._hosts = 0.0, threading.Event(), {}

    # ----- lifecycle -----
    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="cg-ingest").start()

    def _loop(self):
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.interval)

    def run_once(self):
        now = datetime.now(timezone.utc).isoformat()
        self._hosts = {h: c["site_id"] for c in self.store.list_sites() for h in c["allowed_hostnames"]}
        for name, handler in (("access", self._access), ("audit", self._audit)):    # access first: audit events need its policy context
            try:
                self._consume(name, handler)
                self.store._x("INSERT INTO ingest_state(name,last_run_at) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET last_run_at=excluded.last_run_at, last_error=NULL", (name, now))
            except Exception as e:                       # keep running; surface the failure on the dashboard
                self.store._x("INSERT INTO ingest_state(name,last_run_at,last_error) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET last_run_at=excluded.last_run_at, last_error=excluded.last_error",
                              (name, now, _clean(e, 200)))
        if time.time() - self._purged > 3600:
            cut = (datetime.now(timezone.utc) - timedelta(days=self.retention))
            self.store._x("DELETE FROM waf_events WHERE ts < ?", (cut.isoformat(),))
            self.store._x("DELETE FROM traffic_minute WHERE minute < ?", (cut.strftime("%Y-%m-%dT%H:%M"),))
            self._purged = time.time()

    def _consume(self, name, handler):
        path = self.dir / f"{name}.jsonl"
        if not path.exists():
            return
        rows = self.store._q("SELECT offset FROM ingest_state WHERE name=?", (name,))
        off, size = (rows[0]["offset"] if rows else 0), path.stat().st_size
        if size < off: off = 0                           # file was rotated/truncated
        if size == off: return
        with open(path, "rb") as f:
            f.seek(off); chunk = f.read(min(size - off, 2_000_000))
        end = chunk.rfind(b"\n")
        if end < 0: return                               # incomplete last line: wait for the rest
        chunk = chunk[: end + 1]
        ok = bad = 0
        with self.store._l:
            self.store.db.execute("BEGIN")
            try:
                for line in chunk.decode("utf-8", "replace").splitlines():
                    if not line.strip(): continue
                    try: handler(line); ok += 1
                    except ValueError: bad += 1          # malformed line: count it, never stall the pipeline
                self.store.db.execute(
                    "INSERT INTO ingest_state(name,offset,lines,errors,last_data_at) VALUES(?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                    "offset=excluded.offset, lines=lines+excluded.lines, errors=errors+excluded.errors, last_data_at=excluded.last_data_at",
                    (name, off + len(chunk), ok, bad, datetime.now(timezone.utc).isoformat()))
                self.store.db.execute("COMMIT")
            except Exception:
                self.store.db.execute("ROLLBACK"); raise

    # ----- handlers (run inside the batch transaction) -----
    def _access(self, line):
        r = parse_access(line)
        if r["rid"]:
            self.ctx[r["rid"]] = (r["ver"], r["mode"])
            while len(self.ctx) > 20000: self.ctx.popitem(last=False)
        site = self._hosts.get(r["host"])
        if not site or r["uri"] == CANARY: return        # unknown hosts and health canaries are not customer traffic
        none = r["up"] in ("", "-")                       # origin never contacted
        blocked = int(r["status"] == 403 and none)
        rejected = int(r["status"] in (400, 405, 413, 414, 431) and none)
        limited = int(r["status"] == 429 and none)
        b = r["status"] // 100
        self.store.db.execute(
            "INSERT INTO traffic_minute(site_id,minute,total,blocked,rejected,limited,s2,s3,s4,s5,lat_sum,lat_max) VALUES(?,?,1,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(site_id,minute) DO UPDATE SET total=total+1, blocked=blocked+excluded.blocked, rejected=rejected+excluded.rejected, limited=limited+excluded.limited, "
            "s2=s2+excluded.s2, s3=s3+excluded.s3, s4=s4+excluded.s4, s5=s5+excluded.s5, lat_sum=lat_sum+excluded.lat_sum, lat_max=MAX(lat_max,excluded.lat_max)",
            (site, r["minute"], blocked, rejected, limited, int(b == 2), int(b == 3), int(b == 4), int(b == 5), r["rt"], r["rt"]))

    def _audit(self, line):
        e = parse_audit(line)
        site = self._hosts.get(e["host"]) if e else None
        if not e or not site: return
        ver, mode = self.ctx.get(e["id"], (None, None))
        self.store.db.execute(
            "INSERT OR IGNORE INTO waf_events(id,site_id,ts,event_type,rule_id,rule_ids,message,severity,category,score,method,path,query,status,client_ip,user_agent,policy_version,mode,data) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (e["id"], site, e["ts"], e["event_type"], e["rule_id"], json.dumps(e["rule_ids"]), e["message"], e["severity"], e["category"], e["score"],
             e["method"], e["path"], e["query"], e["status"], e["client_ip"], e["user_agent"], ver, mode or None, e["data"]))


# ---------------- queries ----------------
def _since(rng):
    return datetime.now(timezone.utc) - timedelta(minutes=RANGES[rng][0])


def _in(ids):
    return ",".join("?" * len(ids))


def traffic(store, site_ids, rng):
    mins, bucket = RANGES[rng]
    since, now = _since(rng), datetime.now(timezone.utc)
    zero = {"total": 0, "blocked": 0, "rejected": 0, "rate_limited": 0, "allowed": 0, "lat_sum": 0.0, "lat_max": 0.0}
    series, tot = {}, dict(zero)
    t = since.replace(second=0, microsecond=0)
    t -= timedelta(minutes=(t.hour * 60 + t.minute) % bucket)
    while t <= now:
        series[t.strftime("%Y-%m-%dT%H:%M")] = {"allowed": 0, "blocked": 0, "rejected": 0, "limited": 0}; t += timedelta(minutes=bucket)
    if site_ids:
        for r in store._q(f"SELECT * FROM traffic_minute WHERE site_id IN ({_in(site_ids)}) AND minute >= ?", (*site_ids, since.strftime("%Y-%m-%dT%H:%M"))):
            d = datetime.strptime(r["minute"], "%Y-%m-%dT%H:%M")
            d -= timedelta(minutes=(d.hour * 60 + d.minute) % bucket)
            k = d.strftime("%Y-%m-%dT%H:%M"); allowed = r["total"] - r["blocked"] - r["rejected"] - r["limited"]
            b = series.setdefault(k, {"allowed": 0, "blocked": 0, "rejected": 0, "limited": 0})
            b["allowed"] += allowed; b["blocked"] += r["blocked"]; b["rejected"] += r["rejected"]; b["limited"] += r["limited"]
            tot["total"] += r["total"]; tot["blocked"] += r["blocked"]; tot["rejected"] += r["rejected"]; tot["rate_limited"] += r["limited"]; tot["allowed"] += allowed
            tot["lat_sum"] += r["lat_sum"]; tot["lat_max"] = max(tot["lat_max"], r["lat_max"])
    tot["avg_latency_ms"] = round(1000 * tot["lat_sum"] / tot["total"], 1) if tot["total"] else None
    tot["max_latency_ms"] = round(1000 * tot["lat_max"], 1) if tot["total"] else None
    del tot["lat_sum"], tot["lat_max"]
    return {"range": rng, "bucket_minutes": bucket, "series": [{"t": k, **v} for k, v in sorted(series.items())], "totals": tot}


def security(store, site_ids, rng):
    out = {"range": rng, "by_type": {"blocked": 0, "detected": 0}, "by_severity": {s: 0 for s in SEV_ORDER}, "by_category": [], "top_rules": [], "recent": [],
           "note": "Counts are WAF events (matched requests), not unique attacks or attackers."}
    if not site_ids: return out
    a, since = (*site_ids, _since(rng).isoformat()), None
    w = f"site_id IN ({_in(site_ids)}) AND ts >= ?"
    for r in store._q(f"SELECT event_type k, COUNT(*) n FROM waf_events WHERE {w} GROUP BY event_type", a): out["by_type"][r["k"]] = r["n"]
    for r in store._q(f"SELECT severity k, COUNT(*) n FROM waf_events WHERE {w} GROUP BY severity", a):
        if r["k"] in out["by_severity"]: out["by_severity"][r["k"]] = r["n"]
    out["by_category"] = [{"label": r["k"], "value": r["n"]} for r in store._q(f"SELECT category k, COUNT(*) n FROM waf_events WHERE {w} GROUP BY category ORDER BY n DESC LIMIT 8", a)]
    out["top_rules"] = store._q(f"SELECT rule_id, message, COUNT(*) count FROM waf_events WHERE {w} GROUP BY rule_id, message ORDER BY count DESC LIMIT 8", a)
    out["recent"] = store._q(f"SELECT id, site_id, ts, event_type, rule_id, message, severity, path FROM waf_events WHERE {w} AND severity IN ('critical','high') ORDER BY ts DESC LIMIT 8", a)
    return out


def per_site(store, site_ids, rng):
    res = {s: {"site_id": s, "total": 0, "blocked": 0, "detected": 0} for s in site_ids}
    if not site_ids: return []
    since = _since(rng)
    for r in store._q(f"SELECT site_id, SUM(total) t, SUM(blocked) b FROM traffic_minute WHERE site_id IN ({_in(site_ids)}) AND minute >= ? GROUP BY site_id", (*site_ids, since.strftime("%Y-%m-%dT%H:%M"))):
        res[r["site_id"]].update(total=r["t"] or 0, blocked=r["b"] or 0)
    for r in store._q(f"SELECT site_id, COUNT(*) n FROM waf_events WHERE site_id IN ({_in(site_ids)}) AND ts >= ? AND event_type='detected' GROUP BY site_id", (*site_ids, since.isoformat())):
        res[r["site_id"]]["detected"] = r["n"]
    return list(res.values())


def list_events(store, site_id, f, limit=25, offset=0):
    where, a = ["site_id=?"], [site_id]
    if f.get("type") in ("blocked", "detected"): where.append("event_type=?"); a.append(f["type"])
    if f.get("severity") in SEV_ORDER: where.append("severity=?"); a.append(f["severity"])
    if f.get("rule_id"): where.append("rule_id=?"); a.append(str(f["rule_id"])[:12])
    if f.get("since"): where.append("ts >= ?"); a.append(f["since"])
    if f.get("until"): where.append("ts <= ?"); a.append(f["until"])
    if f.get("q"):
        like = "%" + str(f["q"])[:80].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(path LIKE ? ESCAPE '\\' OR query LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\')"); a += [like] * 3
    w = " AND ".join(where)
    total = store._q(f"SELECT COUNT(*) n FROM waf_events WHERE {w}", a)[0]["n"]
    rows = store._q(f"SELECT * FROM waf_events WHERE {w} ORDER BY ts DESC LIMIT ? OFFSET ?", (*a, limit, offset))
    for r in rows: r["rule_ids"] = json.loads(r["rule_ids"] or "[]")
    return {"total": total, "items": rows}


def get_event(store, site_id, eid):
    r = store._q("SELECT * FROM waf_events WHERE site_id=? AND id=?", (site_id, eid))
    if not r: return None
    r[0]["rule_ids"] = json.loads(r[0]["rule_ids"] or "[]"); return r[0]


def pipeline_status(store):
    st = {r["name"]: r for r in store._q("SELECT * FROM ingest_state")}
    if not st: return {"status": "waiting", "detail": "No proxy logs received yet."}
    errs = [r["last_error"] for r in st.values() if r["last_error"]]
    last_run = max((r["last_run_at"] or "" for r in st.values()), default="")
    if last_run and (datetime.now(timezone.utc) - datetime.fromisoformat(last_run)).total_seconds() > 30:
        return {"status": "stalled", "detail": "The event ingestor has not run for over 30 seconds."}
    if errs: return {"status": "error", "detail": errs[0]}
    if not any(r["lines"] for r in st.values()): return {"status": "waiting", "detail": "Ingestor running; no log lines received yet."}
    return {"status": "ok", "detail": "Receiving proxy logs.", "last_data_at": max((r["last_data_at"] or "" for r in st.values()), default=None),
            "malformed_lines": sum(r["errors"] for r in st.values())}
