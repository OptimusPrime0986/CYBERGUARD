"""Email alerts (A09) with per-site thresholds, cooldown de-duplication and a delivery log. Messages carry counts and
rule/site names only: never payloads, tokens or request bodies."""
import json, os, re, smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from .validation import ValidationError

EMAIL_RE = re.compile(r"^[^@\s,;<>]{1,64}@[^@\s,;<>]{1,200}\.[^@\s,;<>]{2,}$")
THRESHOLD_KINDS = {"high_severity": "critical/high firewall detections", "blocked_spike": "blocked requests",
                   "rate_limit": "rate-limited requests", "origin_errors": "origin server errors (5xx)"}
IMMEDIATE_KINDS = ("protection_reduced", "deploy_failed", "pipeline")
DEFAULTS = {"enabled": False, "email": "", "cooldown_minutes": 15,
            "kinds": {"high_severity": {"on": True, "threshold": 5}, "blocked_spike": {"on": True, "threshold": 20},
                      "rate_limit": {"on": True, "threshold": 10}, "origin_errors": {"on": True, "threshold": 5},
                      "protection_reduced": {"on": True}, "deploy_failed": {"on": True}, "pipeline": {"on": True}}}


def validate_settings(raw):
    errs, raw = [], dict(raw or {})
    out = json.loads(json.dumps(DEFAULTS))
    if set(raw) - {"enabled", "email", "cooldown_minutes", "kinds"}: errs.append("unknown alert setting")
    if "enabled" in raw:
        if not isinstance(raw["enabled"], bool): errs.append("enabled must be true or false")
        else: out["enabled"] = raw["enabled"]
    if "email" in raw:
        if raw["email"] and (not isinstance(raw["email"], str) or not EMAIL_RE.match(raw["email"])): errs.append("email must be one valid address")
        else: out["email"] = raw["email"] or ""
    if out["enabled"] and not out["email"]: errs.append("an email address is required to enable alerts")
    cd = raw.get("cooldown_minutes", out["cooldown_minutes"])
    if isinstance(cd, bool) or not isinstance(cd, int) or not 1 <= cd <= 1440: errs.append("cooldown_minutes must be 1-1440")
    else: out["cooldown_minutes"] = cd
    for k, v in (raw.get("kinds") or {}).items():
        if k not in out["kinds"] or not isinstance(v, dict) or set(v) - {"on", "threshold"}: errs.append(f"invalid alert kind {k!r}"); continue
        if "on" in v and not isinstance(v["on"], bool): errs.append(f"{k}.on must be true or false"); continue
        if "threshold" in v:
            if k not in THRESHOLD_KINDS or isinstance(v["threshold"], bool) or not isinstance(v["threshold"], int) or not 1 <= v["threshold"] <= 100000:
                errs.append(f"{k}.threshold must be 1-100000 (threshold kinds only)"); continue
        out["kinds"][k].update(v)
    if errs: raise ValidationError(errs)
    return out


def smtp_sender(env=os.environ):
    host = env.get("CG_SMTP_HOST")
    if not host: return None
    def send(to, subject, body):
        m = EmailMessage(); m["From"] = env.get("CG_SMTP_FROM", "cyberguard@localhost"); m["To"] = to; m["Subject"] = subject; m.set_content(body)
        with smtplib.SMTP(host, int(env.get("CG_SMTP_PORT", "25")), timeout=10) as s:
            if env.get("CG_SMTP_STARTTLS", "false").lower() == "true": s.starttls()
            if env.get("CG_SMTP_USER"): s.login(env["CG_SMTP_USER"], env.get("CG_SMTP_PASSWORD", ""))
            s.send_message(m)
    return send


class AlertEngine:
    def __init__(self, store, send, now=None, window_minutes=5):
        self.store, self.send, self.now, self.window = store, send, now or (lambda: datetime.now(timezone.utc)), window_minutes

    def settings(self, sid): return self.store.kv_get(f"alerts:{sid}", DEFAULTS)

    def notify(self, sid, kind, subject, body, force=False):
        cfg, t = self.settings(sid), self.now()
        key = f"cool:{sid}:{kind}"; last = self.store.kv_get(key)
        if not force and last and t - datetime.fromisoformat(last) < timedelta(minutes=cfg["cooldown_minutes"]): return False   # de-duplicated
        self.store.kv_set(key, t.isoformat())                      # cooldown starts on attempt: a down mail server must not be hammered
        try:
            if not self.send: raise RuntimeError("SMTP is not configured (set CG_SMTP_HOST)")
            self.send(cfg["email"], subject, body); status, err = "sent", None
        except Exception as e:
            status, err = "failed", f"{type(e).__name__}: {e}"
        self.store.add_notification(sid, kind, cfg["email"], status, err, subject)
        return status == "sent"

    def _counts(self, sid):
        t = self.now(); since = (t - timedelta(minutes=self.window))
        hi = self.store._q("SELECT COUNT(*) n FROM waf_events WHERE site_id=? AND ts>=? AND severity IN ('critical','high')", (sid, since.isoformat()))[0]["n"]
        tr = self.store._q("SELECT COALESCE(SUM(blocked),0) b, COALESCE(SUM(limited),0) l, COALESCE(SUM(s5),0) e FROM traffic_minute WHERE site_id=? AND minute>=?",
                           (sid, since.strftime("%Y-%m-%dT%H:%M")))[0]
        return {"high_severity": hi, "blocked_spike": tr["b"], "rate_limit": tr["l"], "origin_errors": tr["e"]}

    def run_once(self):
        sites = {c["site_id"]: c for c in self.store.list_sites()}
        live = {sid: self.settings(sid) for sid in sites}
        live = {sid: c for sid, c in live.items() if c["enabled"] and c["email"]}
        for sid, cfg in live.items():                                  # threshold alerts
            for kind, n in self._counts(sid).items():
                k = cfg["kinds"][kind]
                if k["on"] and n >= k["threshold"]:
                    self.notify(sid, kind, f"[CyberGuard] {sites[sid]['name']}: {n} {THRESHOLD_KINDS[kind]} in {self.window} minutes",
                                f"Site: {sites[sid]['name']} ({sites[sid]['hostname']})\nCount: {n} {THRESHOLD_KINDS[kind]} in the last {self.window} minutes (alert threshold {k['threshold']}).\n"
                                "Open the CyberGuard dashboard for details. This message contains no request content.")
        cur = self.store.kv_get("alerts:audit_cursor", 0); top = cur       # change alerts, driven by the admin audit log
        for a in self.store._q("SELECT * FROM audit_events WHERE id>? ORDER BY id", (cur,)):
            top = a["id"]; sid = a["site_id"]
            if sid not in live or not a["action"].startswith("policy."): continue
            if a["result"] == "success" and live[sid]["kinds"]["protection_reduced"]["on"]:
                try: before, after = json.loads(a["previous_value"] or "{}").get("mode"), json.loads(a["new_value"] or "{}").get("mode")
                except ValueError: continue
                if before == "blocking" and after in ("monitoring", "disabled"):
                    self.notify(sid, "protection_reduced", f"[CyberGuard] {sites[sid]['name']}: protection reduced to '{after}'",
                                f"Firewall mode for {sites[sid]['name']} changed from blocking to {after} by {a['actor']} at {a['ts']}.", force=True)
            elif a["result"].startswith("failed") and live[sid]["kinds"]["deploy_failed"]["on"]:
                self.notify(sid, "deploy_failed", f"[CyberGuard] {sites[sid]['name']}: a policy change failed",
                            f"A policy change by {a['actor']} was NOT applied ({a['result'][:120]}). The previous policy is still in force.", force=True)
        if top != cur: self.store.kv_set("alerts:audit_cursor", top)
        from .events import pipeline_status
        ps = pipeline_status(self.store)
        if ps["status"] in ("stalled", "error"):
            for sid, cfg in live.items():
                if cfg["kinds"]["pipeline"]["on"]:
                    self.notify(sid, "pipeline", f"[CyberGuard] event pipeline {ps['status']}", f"The firewall event pipeline reports: {ps['status']}. {ps['detail'][:150]}")
