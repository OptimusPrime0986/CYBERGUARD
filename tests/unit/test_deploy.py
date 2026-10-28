import sqlite3, threading, json
import pytest
from cyberguard.deployer import ConflictError, DeploymentError, NotFound
from cyberguard.validation import ValidationError
from .conftest import site

def reg(dep, sid="shop", host="shop.example.com", mode="blocking"):
    return dep.register_site("alice", site(sid, host), {"mode": mode})

def test_register_applies_and_verifies(env):
    dep, eng, store, _ = env
    st = reg(dep)
    assert (st["effective_mode"], st["effective_version"], st["sync_state"]) == ("blocking", 1, "in_sync")
    assert eng.calls == ["validate", "reload", "verify"] and eng.running == dep.active_release()

def test_mode_change_success_and_audit(env):
    dep, eng, store, _ = env; reg(dep)
    st = dep.set_policy("alice", "shop", {"mode": "monitoring"}, 1)
    assert st["effective_mode"] == "monitoring" and st["effective_version"] == 2
    a = [x for x in store.audit_list("shop") if x["action"] == "policy.update"][-1]
    assert a["result"] == "success" and json.loads(a["previous_value"])["mode"] == "blocking" and a["actor"] == "alice"

def test_validation_failure_keeps_last_known_good_and_never_reloads(env):
    dep, eng, store, _ = env; reg(dep)
    good_release, before = dep.active_release(), list(eng.calls)
    eng.fail_validate = True
    with pytest.raises(DeploymentError) as e: dep.set_policy("alice", "shop", {"mode": "disabled"}, 1)
    assert e.value.stage == "validation"
    assert dep.active_release() == good_release and eng.running == good_release      # nothing changed
    assert "reload" not in eng.calls[len(before):]
    st = dep.protection_state("shop")
    assert st["effective_mode"] == "blocking" and st["requested_mode"] == "disabled" and st["requested_status"] == "failed"
    assert "failed at validation" in store.audit_list("shop")[-1]["result"]

def test_verification_failure_rolls_back_engine_and_reports_it(env):
    dep, eng, store, _ = env; reg(dep)
    good = dep.active_release(); eng.fail_verify_versions = {2}
    with pytest.raises(DeploymentError) as e: dep.set_policy("alice", "shop", {"mode": "disabled"}, 1)
    assert e.value.stage == "verification" and e.value.rolled_back is True
    assert dep.active_release() == good and eng.running == good                        # engine restored
    st = dep.protection_state("shop")
    assert st["effective_mode"] == "blocking" and st["sync_state"] == "in_sync" and "verification" in st["last_error"]

def test_reload_failure_rolls_back(env):
    dep, eng, *_ = env; reg(dep); good = dep.active_release(); eng.fail_reload = True
    with pytest.raises(DeploymentError): dep.set_policy("alice", "shop", {"mode": "monitoring"}, 1)
    assert dep.active_release() == good

def test_failed_first_registration_leaves_nothing_behind(env):
    dep, eng, store, _ = env; eng.fail_validate = True
    with pytest.raises(DeploymentError): reg(dep)
    assert store.list_sites() == [] and dep.active_release() is None
    eng.fail_validate = False
    assert reg(dep)["sync_state"] == "in_sync"                                         # id is reusable

def test_stale_expected_version_conflicts(env):
    dep, *_ = env; reg(dep)
    dep.set_policy("a", "shop", {"mode": "monitoring"}, 1)
    with pytest.raises(ConflictError): dep.set_policy("b", "shop", {"mode": "disabled"}, 1)

def test_concurrent_updates_only_one_wins(env):
    dep, *_ = env; reg(dep); res = []
    def go(mode):
        try: dep.set_policy("t", "shop", {"mode": mode}, 1); res.append("ok")
        except ConflictError: res.append("conflict")
    ts = [threading.Thread(target=go, args=(m,)) for m in ("monitoring", "disabled", "monitoring", "disabled")]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sorted(res) == ["conflict"] * 3 + ["ok"]

def test_invalid_policy_rejected_and_audited(env):
    dep, eng, store, _ = env; reg(dep); n = len(eng.calls)
    with pytest.raises(ValidationError): dep.set_policy("a", "shop", {"mode": "pause"}, 1)
    assert len(eng.calls) == n and store.audit_list("shop")[-1]["result"].startswith("rejected")

def test_rollback_restores_old_config_as_new_version(env):
    dep, _, store, _ = env; reg(dep)
    dep.set_policy("a", "shop", {"mode": "disabled"}, 1)
    st = dep.rollback("a", "shop", 1, 2)
    assert st["effective_mode"] == "blocking" and st["effective_version"] == 3
    assert store.get_policy("shop", 3)["rollback_of"] == 1
    with pytest.raises(NotFound): dep.rollback("a", "shop", 99, 3)

def test_cannot_roll_back_to_failed_version(env):
    dep, eng, *_ = env; reg(dep); eng.fail_validate = True
    with pytest.raises(DeploymentError): dep.set_policy("a", "shop", {"mode": "disabled"}, 1)
    eng.fail_validate = False
    with pytest.raises(NotFound): dep.rollback("a", "shop", 2, 1)

def test_one_sites_change_does_not_alter_the_other(env):
    dep, _, _, root = env; reg(dep, "shop", "shop.example.com"); reg(dep, "blog", "blog.example.com")
    rel = lambda: (root / "active" / "nginx" / "10-site-blog.conf").read_text().split("release")[0]
    before = rel(); dep.set_policy("a", "shop", {"mode": "disabled"}, 1)
    assert rel() == before and dep.protection_state("blog")["effective_mode"] == "blocking"

def test_remove_site(env):
    dep, _, store, _ = env; reg(dep, "shop", "shop.example.com"); reg(dep, "blog", "blog.example.com")
    dep.remove_site("a", "shop")
    with pytest.raises(NotFound): dep.set_policy("a", "shop", {"mode": "disabled"}, 1)
    assert dep.protection_state("blog")["sync_state"] == "in_sync"
    assert any(x["action"] == "site.remove" for x in store.audit_list("shop"))      # audit preserved

def test_audit_is_append_only(env):
    dep, _, store, _ = env; reg(dep)
    with pytest.raises(sqlite3.DatabaseError): store.db.execute("UPDATE audit_events SET result='x'")
    with pytest.raises(sqlite3.DatabaseError): store.db.execute("DELETE FROM audit_events")

def test_reconcile_detects_engine_drift_and_unknown(env):
    dep, eng, store, root = env; reg(dep)
    assert dep.reconcile()["shop"]["sync_state"] == "in_sync"
    eng.running = None                                         # simulate proxy restarted without config
    assert dep.reconcile()["shop"]["sync_state"] == "unverified"
    (root / "active").unlink()                                 # no active release at all
    assert dep.reconcile()["shop"]["sync_state"] == "unknown"  # never reported as protected
