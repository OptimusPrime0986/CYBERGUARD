import json, os, pytest
from pathlib import Path
from cyberguard.deployer import Deployer
from cyberguard.engine import Engine, VerifyResult
from cyberguard.store import Store
from cyberguard.validation import AdminPolicy


class FakeEngine(Engine):
    """Simulates nginx semantics: the RUNNING release only changes on a successful reload."""
    def __init__(self, root):
        self.root, self.calls, self.running = Path(root), [], None
        self.fail_validate = self.fail_reload = False
        self.fail_verify_versions = set()   # policy versions whose verification fails
    def _active(self):
        l = self.root / "active"; return int(os.readlink(l).rsplit("/", 1)[-1]) if l.is_symlink() else None
    def validate(self):
        self.calls.append("validate")
        return (False, "nginx: [emerg] simulated bad config") if self.fail_validate else (True, "ok")
    def reload(self):
        self.calls.append("reload")
        if self.fail_reload: return False, "reload failed"
        self.running = self._active(); return True, "ok"
    def verify(self, exps):
        self.calls.append("verify"); out, ok = {}, True
        m = json.loads((self.root / "releases" / str(self.running) / "manifest.json").read_text()) if self.running else {"sites": {}}
        for e in exps:
            s = m["sites"].get(e.site_id)
            good = bool(s) and s["policy_version"] == e.policy_version and s["mode"] == e.mode and e.policy_version not in self.fail_verify_versions
            out[e.site_id] = "config loaded; canary ok" if good else "mismatch"; ok &= good
        return VerifyResult(ok, out)


@pytest.fixture
def admin():
    return AdminPolicy(allowed_origin_hosts=frozenset({"origin"}), resolver=lambda h: ["93.184.216.34"])

@pytest.fixture
def env(tmp_path, admin):
    root = tmp_path / "cg"; root.mkdir()
    eng = FakeEngine(root); store = Store(str(tmp_path / "s.db"))
    return Deployer(store, eng, root, admin), eng, store, root

def site(sid="shop", host="shop.example.com"):
    return {"site_id": sid, "name": sid.title(), "hostname": host, "origin_host": "origin", "origin_port": 5000, "origin_scheme": "http"}
