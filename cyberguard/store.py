import json, sqlite3, threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS sites(site_id TEXT PRIMARY KEY, config TEXT NOT NULL, created_at TEXT NOT NULL, deleted_at TEXT);
CREATE TABLE IF NOT EXISTS policies(site_id TEXT NOT NULL, version INTEGER NOT NULL, config TEXT NOT NULL,
  status TEXT NOT NULL, error TEXT, rollback_of INTEGER, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(site_id, version));
CREATE TABLE IF NOT EXISTS site_state(site_id TEXT PRIMARY KEY, effective_version INTEGER, effective_mode TEXT,
  release INTEGER, sync_state TEXT NOT NULL, last_error TEXT, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS releases(release INTEGER PRIMARY KEY AUTOINCREMENT, manifest TEXT, validation_result TEXT,
  deployment_result TEXT, error TEXT, created_at TEXT NOT NULL, completed_at TEXT);
CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
  site_id TEXT, action TEXT NOT NULL, previous_value TEXT, new_value TEXT, result TEXT NOT NULL, correlation_id TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','owner','analyst')), status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS site_access(site_id TEXT NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY(site_id, user_id));
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
"""


def now():
    return datetime.now(timezone.utc).isoformat()


EVENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS waf_events(id TEXT PRIMARY KEY, site_id TEXT NOT NULL, ts TEXT NOT NULL, event_type TEXT NOT NULL,
  rule_id TEXT, rule_ids TEXT, message TEXT, severity TEXT, category TEXT, score INTEGER, method TEXT, path TEXT, query TEXT,
  status INTEGER, client_ip TEXT, user_agent TEXT, policy_version INTEGER, mode TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS ix_events_site_ts ON waf_events(site_id, ts);
CREATE TABLE IF NOT EXISTS traffic_minute(site_id TEXT NOT NULL, minute TEXT NOT NULL, total INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0, rejected INTEGER NOT NULL DEFAULT 0, s2 INTEGER NOT NULL DEFAULT 0, s3 INTEGER NOT NULL DEFAULT 0,
  s4 INTEGER NOT NULL DEFAULT 0, s5 INTEGER NOT NULL DEFAULT 0, limited INTEGER NOT NULL DEFAULT 0, lat_sum REAL NOT NULL DEFAULT 0, lat_max REAL NOT NULL DEFAULT 0,
  PRIMARY KEY(site_id, minute));
CREATE TABLE IF NOT EXISTS kv(name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, site_id TEXT, kind TEXT NOT NULL,
  destination TEXT, status TEXT NOT NULL, error TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS ingest_state(name TEXT PRIMARY KEY, offset INTEGER NOT NULL DEFAULT 0, lines INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0, last_data_at TEXT, last_run_at TEXT, last_error TEXT);
"""


class Store:
    """SQLite for Phase 2 only; the spec's PostgreSQL schema arrives in Phase 5."""
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.db.executescript(EVENT_SCHEMA)
        self._migrate()
        self._l = threading.RLock()

    def _migrate(self):
        """Add columns introduced after first release without touching existing data."""
        for table, cols in (("traffic_minute", {"limited": "INTEGER NOT NULL DEFAULT 0"}),
                            ("users", {"totp_secret": "TEXT", "totp_enabled": "INTEGER NOT NULL DEFAULT 0", "totp_last_step": "INTEGER NOT NULL DEFAULT 0"})):
            have = {r[1] for r in self.db.execute(f"PRAGMA table_info({table})")}
            for c, t in cols.items():
                if c not in have: self.db.execute(f"ALTER TABLE {table} ADD COLUMN {c} {t}")

    def kv_get(self, name, default=None):
        r = self._q("SELECT value FROM kv WHERE name=?", (name,)); return json.loads(r[0]["value"]) if r else default
    def kv_set(self, name, value): self._x("INSERT OR REPLACE INTO kv VALUES(?,?)", (name, json.dumps(value)))
    def add_notification(self, site_id, kind, dest, status, error, summary):
        self._x("INSERT INTO notifications(ts,site_id,kind,destination,status,error,summary) VALUES(?,?,?,?,?,?,?)", (now(), site_id, kind, dest, status, (error or "")[:300] or None, summary[:300]))
    def list_notifications(self, site_id, limit=30): return self._q("SELECT * FROM notifications WHERE site_id=? ORDER BY id DESC LIMIT ?", (site_id, limit))
    def get_user(self, uid):
        r = self._q("SELECT * FROM users WHERE id=?", (uid,)); return r[0] if r else None
    def set_totp(self, uid, secret_enc, enabled, step=0): self._x("UPDATE users SET totp_secret=?, totp_enabled=?, totp_last_step=? WHERE id=?", (secret_enc, int(enabled), step, uid))
    def set_totp_step(self, uid, step): self._x("UPDATE users SET totp_last_step=? WHERE id=?", (step, uid))

    def _q(self, sql, a=()):
        with self._l: return [dict(r) for r in self.db.execute(sql, a).fetchall()]

    def _x(self, sql, a=()):
        with self._l: return self.db.execute(sql, a).lastrowid

    # sites
    def add_site(self, site): self._x("INSERT INTO sites VALUES(?,?,?,NULL)", (site.site_id, json.dumps(site.to_dict()), now()))
    def get_site(self, sid):
        r = self._q("SELECT config FROM sites WHERE site_id=? AND deleted_at IS NULL", (sid,))
        return json.loads(r[0]["config"]) if r else None
    def list_sites(self): return [json.loads(r["config"]) for r in self._q("SELECT config FROM sites WHERE deleted_at IS NULL ORDER BY site_id")]
    def delete_site(self, sid): self._x("UPDATE sites SET deleted_at=? WHERE site_id=?", (now(), sid))
    def site_id_used(self, sid): return bool(self._q("SELECT 1 FROM sites WHERE site_id=?", (sid,)))

    # policies
    def latest_version(self, sid):
        return self._q("SELECT COALESCE(MAX(version),0) v FROM policies WHERE site_id=?", (sid,))[0]["v"]
    def add_policy(self, sid, version, policy, actor, status, error=None, rollback_of=None):
        self._x("INSERT INTO policies VALUES(?,?,?,?,?,?,?,?)",
                (sid, version, json.dumps(policy.to_dict()), status, error, rollback_of, actor, now()))
    def get_policy(self, sid, version):
        r = self._q("SELECT * FROM policies WHERE site_id=? AND version=?", (sid, version))
        if not r: return None
        r = r[0]; r["config"] = json.loads(r["config"]); return r
    def list_policies(self, sid):
        return [dict(r, config=json.loads(r["config"])) for r in self._q("SELECT * FROM policies WHERE site_id=? ORDER BY version", (sid,))]

    # state
    def get_state(self, sid):
        r = self._q("SELECT * FROM site_state WHERE site_id=?", (sid,)); return r[0] if r else None
    def set_state(self, sid, **f):
        cur = self.get_state(sid) or {"effective_version": None, "effective_mode": None, "release": None,
                                      "sync_state": "pending", "last_error": None}
        cur.update(f)
        self._x("INSERT OR REPLACE INTO site_state VALUES(?,?,?,?,?,?,?)",
                (sid, cur["effective_version"], cur["effective_mode"], cur["release"], cur["sync_state"], cur["last_error"], now()))

    # releases (= deployment records)
    def new_release(self, manifest): return self._x("INSERT INTO releases(manifest,created_at) VALUES(?,?)", (json.dumps(manifest), now()))
    def update_release(self, rid, **f):
        for k, v in f.items():
            assert k in ("validation_result", "deployment_result", "error")
            self._x(f"UPDATE releases SET {k}=? WHERE release=?", (v, rid))
        self._x("UPDATE releases SET completed_at=? WHERE release=?", (now(), rid))

    # audit
    def audit(self, actor, site_id, action, prev, new, result, correlation_id):
        self._x("INSERT INTO audit_events(ts,actor,site_id,action,previous_value,new_value,result,correlation_id) VALUES(?,?,?,?,?,?,?,?)",
                (now(), actor, site_id, action, json.dumps(prev), json.dumps(new), result, correlation_id))
    def audit_list(self, site_id=None):
        return self._q("SELECT * FROM audit_events WHERE (? IS NULL OR site_id=?) ORDER BY id", (site_id, site_id))

    # users / sessions / access
    def create_user(self, email, pw_hash, role):
        return self._x("INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)", (email, pw_hash, role, now()))
    def get_user_by_email(self, email):
        r = self._q("SELECT * FROM users WHERE email=?", (email,)); return r[0] if r else None
    def list_users(self): return self._q("SELECT id,email,role,status,created_at,totp_enabled FROM users ORDER BY id")
    def create_session(self, sid, user_id, expires_at): self._x("INSERT INTO sessions VALUES(?,?,?)", (sid, user_id, expires_at))
    def delete_session(self, sid): self._x("DELETE FROM sessions WHERE sid=?", (sid,))
    def session_user(self, sid):
        r = self._q("SELECT u.id,u.email,u.role,u.status,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.sid=?", (sid,))
        if not r: return None
        if r[0]["expires_at"] < now(): self.delete_session(sid); return None
        return r[0]
    def grant(self, site_id, user_id): self._x("INSERT OR IGNORE INTO site_access VALUES(?,?)", (site_id, user_id))
    def has_access(self, site_id, user_id): return bool(self._q("SELECT 1 FROM site_access WHERE site_id=? AND user_id=?", (site_id, user_id)))
    def accessible_sites(self, user_id): return [r["site_id"] for r in self._q("SELECT site_id FROM site_access WHERE user_id=?", (user_id,))]
