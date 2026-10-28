"""Policy manager: validate -> stage -> nginx -t -> reload -> verify -> record, with rollback."""
import fcntl, json, os, threading, uuid
from contextlib import contextmanager
from pathlib import Path

from datetime import datetime, timezone
from . import tls as tlsmod
from .engine import SiteExpectation
from .render import render_release
from .validation import Policy, Site, validate_policy, validate_site, ValidationError


class ConflictError(Exception): pass
class NotFound(Exception): pass


class DeploymentError(Exception):
    def __init__(self, stage, message, rolled_back, release):
        super().__init__(f"{stage}: {message}")
        self.stage, self.message, self.rolled_back, self.release = stage, message, rolled_back, release


class Deployer:
    def __init__(self, store, engine, root, admin):
        self.store, self.engine, self.root, self.admin = store, engine, Path(root), admin
        (self.root / "releases").mkdir(parents=True, exist_ok=True)
        self._tl = threading.RLock()

    # ---------- locking: one change at a time, across threads and processes ----------
    @contextmanager
    def _guard(self):
        with self._tl:                              # RLock: re-entrant within a thread
            self._depth = getattr(self, "_depth", 0) + 1
            if self._depth > 1:                     # nested call (e.g. rollback -> set_policy): already hold the file lock
                try: yield
                finally: self._depth -= 1
                return
            with open(self.root / ".deploy.lock", "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try: yield
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN); self._depth -= 1

    # ---------- release plumbing ----------
    def active_release(self):
        link = self.root / "active"
        return int(os.readlink(link).rsplit("/", 1)[-1]) if link.is_symlink() else None

    def _set_active(self, rid):
        link, tmp = self.root / "active", self.root / ".active.tmp"
        if rid is None:
            if link.is_symlink(): link.unlink()
            return
        if tmp.is_symlink() or tmp.exists(): tmp.unlink()
        os.symlink(f"releases/{rid}", tmp)
        os.replace(tmp, link)                      # atomic swap

    def _manifest(self, rid):
        return json.loads((self.root / "releases" / str(rid) / "manifest.json").read_text())

    def _expectations(self, manifest):
        return [SiteExpectation(s, v["hostname"], v["policy_version"], v["mode"], manifest["release"], v.get("https", "off"))
                for s, v in sorted(manifest["sites"].items())]

    def _entries(self, override=None, drop=None):
        """Other sites are rebuilt from their EFFECTIVE policy only, so one site's change cannot alter another's."""
        entries = {}
        for cfg in self.store.list_sites():
            sid = cfg["site_id"]
            if sid == drop: continue
            if override and sid == override[0]:
                entries[sid] = (Site.from_dict(cfg), override[1], override[2]); continue
            st = self.store.get_state(sid)
            if st and st["effective_version"]:
                pol = Policy.from_dict(self.store.get_policy(sid, st["effective_version"])["config"])
                entries[sid] = (Site.from_dict(cfg), pol, st["effective_version"])
        return entries

    def _deploy(self, entries):
        rid = self.store.new_release({"pending": True})
        prev = self.active_release()
        final, stage = self.root / "releases" / str(rid), self.root / "releases" / f"{rid}.tmp"
        files = render_release(rid, str(self.root), entries, tls_sites=frozenset(x for x in entries if tlsmod.status(self.root, x)["installed"]),
                               trusted_proxies=self.admin.trusted_proxies, https_port=self.admin.public_https_port)
        for rel, content in files.items():
            p = stage / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)
        os.rename(stage, final)
        manifest = json.loads(files["manifest.json"])

        def fail(stage_name, msg, reload_needed):
            self._set_active(prev)
            rolled = True
            if reload_needed and prev is not None:       # engine already took the bad release; restore it
                ok, _ = self.engine.reload()
                rolled = ok and self.engine.verify(self._expectations(self._manifest(prev))).ok
            self.store.update_release(rid, deployment_result="failed", error=f"{stage_name}: {msg}"[:2000])
            raise DeploymentError(stage_name, msg, rolled, rid)

        self._set_active(rid)
        ok, msg = self.engine.validate()                 # nginx -t only: running workers untouched
        self.store.update_release(rid, validation_result="passed" if ok else "failed")
        if not ok: fail("validation", msg, False)
        ok, msg = self.engine.reload()
        if not ok: fail("reload", msg, True)
        res = self.engine.verify(self._expectations(manifest))
        if not res.ok: fail("verification", json.dumps(res.details), True)
        self.store.update_release(rid, deployment_result="applied")
        return rid

    # ---------- public operations ----------
    def register_site(self, actor, raw_site, raw_policy=None, correlation_id=None):
        cid = correlation_id or uuid.uuid4().hex
        with self._guard():
            try:
                site, pol = validate_site(raw_site, self.admin), validate_policy(self._stamp(raw_policy, actor, ()), self.admin)
                self._need_tls(site.site_id, pol)
            except ValidationError as e:
                self.store.audit(actor, (raw_site or {}).get("site_id"), "site.register", None, None, f"rejected: {e}", cid); raise
            if self.store.site_id_used(site.site_id): raise ConflictError(f"site_id {site.site_id!r} already used")
            try:
                rid = self._deploy({**self._entries(), site.site_id: (site, pol, 1)})
            except DeploymentError as e:
                self.store.audit(actor, site.site_id, "site.register", None, pol.to_dict(), f"failed at {e.stage}", cid); raise
            self.store.add_site(site); self.store.add_policy(site.site_id, 1, pol, actor, "applied")
            self.store.set_state(site.site_id, effective_version=1, effective_mode=pol.mode, release=rid, sync_state="in_sync", last_error=None)
            self.store.audit(actor, site.site_id, "site.register", None, {"site": site.to_dict(), "policy": pol.to_dict()}, "success", cid)
            return self.protection_state(site.site_id)

    def set_policy(self, actor, site_id, raw_policy, expected_version, correlation_id=None, rollback_of=None):
        cid = correlation_id or uuid.uuid4().hex
        action = "policy.rollback" if rollback_of else "policy.update"
        with self._guard():
            site = self._site(site_id)
            st = self.store.get_state(site_id)
            if st["effective_version"] != expected_version:
                raise ConflictError(f"expected effective version {expected_version}, current is {st['effective_version']}")
            prev = self.store.get_policy(site_id, st["effective_version"])["config"]
            try:
                pol = validate_policy(self._stamp(raw_policy, actor, prev.get("exclusions") or ()), self.admin)
                self._need_tls(site_id, pol)
            except ValidationError as e:
                self.store.audit(actor, site_id, action, prev, raw_policy, f"rejected: {e}", cid); raise
            ver = self.store.latest_version(site_id) + 1
            try:
                rid = self._deploy(self._entries(override=(site_id, pol, ver)))
            except DeploymentError as e:
                self.store.add_policy(site_id, ver, pol, actor, "failed", f"{e.stage}: {e.message}"[:2000], rollback_of)
                self.store.set_state(site_id, sync_state="in_sync" if e.rolled_back else "out_of_sync", last_error=f"{e.stage}: {e.message}"[:2000])
                self.store.audit(actor, site_id, action, prev, pol.to_dict(), f"failed at {e.stage}; last known good kept (rollback_verified={e.rolled_back})", cid)
                raise
            self.store.add_policy(site_id, ver, pol, actor, "applied", None, rollback_of)
            self.store.set_state(site_id, effective_version=ver, effective_mode=pol.mode, release=rid, sync_state="in_sync", last_error=None)
            self.store.audit(actor, site_id, action, prev, pol.to_dict(), "success", cid)
            return self.protection_state(site_id)

    def _stamp(self, raw, actor, previous):
        """Server decides who/when created each exclusion (clients cannot forge it); unchanged ones keep their original stamp."""
        raw = dict(raw or {})
        if not isinstance(raw.get("exclusions"), (list, tuple)): return raw
        old = {(e.get("rule_id"), e.get("path"), e.get("target")): e for e in previous}
        now, out = datetime.now(timezone.utc).isoformat(timespec="seconds"), []
        for e in raw["exclusions"]:
            if not isinstance(e, dict): out.append(e); continue
            o = old.get((e.get("rule_id"), e.get("path"), e.get("target")))
            out.append({**e, "created_by": o["created_by"] if o else actor, "created_at": o["created_at"] if o else now})
        raw["exclusions"] = out
        return raw

    def _need_tls(self, site_id, pol):
        if pol.https != "off" and not tlsmod.status(self.root, site_id)["installed"]:
            raise ValidationError(["HTTPS needs a certificate: install one (or generate a self-signed one) before turning it on"])

    def expire_exclusions(self, actor="system"):
        """Remove exclusions past their expiry date through a normal, verified policy change."""
        today, done = datetime.now(timezone.utc).strftime("%Y-%m-%d"), []
        for cfg in self.store.list_sites():
            sid, st = cfg["site_id"], self.store.get_state(cfg["site_id"])
            if not st or not st["effective_version"]: continue
            pol = self.store.get_policy(sid, st["effective_version"])["config"]
            ex = pol.get("exclusions") or []
            keep = [e for e in ex if not (e.get("expires") and e["expires"] < today)]
            if len(keep) != len(ex):
                try: self.set_policy(actor, sid, {**pol, "exclusions": keep}, st["effective_version"]); done.append(sid)
                except Exception: pass                   # stays expired-but-listed; render already ignores it
        return done

    def rollback(self, actor, site_id, to_version, expected_version, correlation_id=None):
        with self._guard():
            old = self.store.get_policy(site_id, to_version)
            if not old or old["status"] != "applied":
                raise NotFound(f"version {to_version} is not a previously applied (known-good) policy")
            return self.set_policy(actor, site_id, old["config"], expected_version, correlation_id, rollback_of=to_version)

    def remove_site(self, actor, site_id, correlation_id=None):
        cid = correlation_id or uuid.uuid4().hex
        with self._guard():
            self._site(site_id)
            try:
                self._deploy(self._entries(drop=site_id))
            except DeploymentError as e:
                self.store.audit(actor, site_id, "site.remove", None, None, f"failed at {e.stage}", cid); raise
            self.store.delete_site(site_id); self.store.set_state(site_id, sync_state="removed")
            self.store.audit(actor, site_id, "site.remove", None, None, "success", cid)

    def protection_state(self, site_id):
        self._site(site_id)
        st, latest = self.store.get_state(site_id), self.store.latest_version(site_id)
        req = self.store.get_policy(site_id, latest)
        return {"site_id": site_id, "requested_mode": req["config"]["mode"], "requested_version": latest,
                "requested_status": req["status"], "effective_mode": st["effective_mode"],
                "effective_version": st["effective_version"], "sync_state": st["sync_state"],
                "last_error": st["last_error"], "active_release": self.active_release()}

    def reconcile(self, actor="system"):
        """Compare DB vs active release vs RUNNING engine. Unknown is never reported as protected."""
        cid = uuid.uuid4().hex
        with self._guard():
            rid, report = self.active_release(), {}
            manifest = self._manifest(rid) if rid is not None else {"release": None, "sites": {}}
            verified = {}
            if rid is not None:
                verified = self.engine.verify(self._expectations(manifest)).details
            for cfg in self.store.list_sites():
                sid, st = cfg["site_id"], self.store.get_state(cfg["site_id"])
                m = manifest["sites"].get(sid)
                if rid is None: state = "unknown"
                elif not m or m["policy_version"] != st["effective_version"]: state = "out_of_sync"
                elif verified.get(sid, "").startswith("config loaded") and "NOT blocked" not in verified[sid]: state = "in_sync"
                else: state = "unverified"
                self.store.set_state(sid, sync_state=state)
                report[sid] = {"sync_state": state, "detail": verified.get(sid)}
            self.store.audit(actor, None, "reconcile", None, report, "completed", cid)
            return report

    def reapply(self, actor, correlation_id=None):
        """Re-render and redeploy the current effective state (e.g. after a certificate was replaced)."""
        cid = correlation_id or uuid.uuid4().hex
        with self._guard():
            try: rid = self._deploy(self._entries())
            except DeploymentError as e:
                self.store.audit(actor, None, "deploy.reapply", None, None, f"failed at {e.stage}", cid); raise
            self.store.audit(actor, None, "deploy.reapply", None, {"release": rid}, "success", cid); return rid

    def policy_of(self, site_id):
        st = self.store.get_state(site_id)
        return Policy.from_dict(self.store.get_policy(site_id, st["effective_version"])["config"])

    def tls_status(self, site_id): return tlsmod.status(self.root, site_id)

    def site_health(self, site_id):
        """Checks the RUNNING engine for this site against the active release. Returns sanitized status only."""
        self._site(site_id)
        rid = self.active_release()
        m = self._manifest(rid) if rid is not None else {"release": None, "sites": {}}
        if site_id not in m["sites"]:
            return {"status": "unknown", "detail": "site is not part of the active release"}
        exp = [e for e in self._expectations(m) if e.site_id == site_id]
        res = self.engine.verify(exp)
        return {"status": "healthy" if res.ok else "unhealthy", "detail": res.details.get(site_id), "release": rid}

    def _site(self, site_id):
        if not self.store.get_site(site_id): raise NotFound(f"site {site_id!r} not found")
        return site_id
