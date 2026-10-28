"""Temporary operator CLI. Authentication/authorization arrive with the Phase 3 API; --actor is NOT authenticated."""
import argparse, json, os, sys
from .deployer import Deployer, ConflictError, DeploymentError, NotFound
from .engine import FileAgentEngine
from .store import Store
from .validation import AdminPolicy, ValidationError


def build():
    root = os.environ.get("CG_ROOT", "/etc/cyberguard")
    admin = AdminPolicy(
        allowed_origin_hosts=frozenset(filter(None, os.environ.get("CG_ALLOWED_ORIGIN_HOSTS", "").split(","))),
        allowed_origin_cidrs=tuple(filter(None, os.environ.get("CG_ALLOWED_ORIGIN_CIDRS", "").split(","))),
        allow_site_wide_exclusions=os.environ.get("CG_ALLOW_SITE_WIDE_EXCLUSIONS", "false").lower() == "true",
        trusted_proxies=tuple(filter(None, os.environ.get("CG_TRUSTED_PROXIES", "").split(","))),
        public_https_port=int(os.environ.get("CG_PUBLIC_HTTPS_PORT", "443")))
    engine = FileAgentEngine(f"{root}/agent", os.environ.get("CG_STATE_URL", "http://proxy:9000"),
                             os.environ.get("CG_PUBLIC_URL", "http://proxy:8000"),
                             https_url=os.environ.get("CG_PUBLIC_HTTPS_URL", "https://proxy:8443"))
    return Deployer(Store(os.environ.get("CG_DB", "/var/lib/cyberguard/state.db")), engine, root, admin)


def main(argv=None):
    p = argparse.ArgumentParser(prog="cyberguard"); p.add_argument("--actor", default="cli:local")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("site-add")
    for f in ("id", "name", "hostname", "origin-host"): a.add_argument(f"--{f}", required=True)
    a.add_argument("--origin-port", type=int, required=True); a.add_argument("--scheme", default="https")
    a.add_argument("--mode", default="blocking")
    m = sub.add_parser("set-mode"); m.add_argument("--site", required=True); m.add_argument("--mode", required=True); m.add_argument("--expected-version", type=int, required=True)
    r = sub.add_parser("rollback"); r.add_argument("--site", required=True); r.add_argument("--to", type=int, required=True); r.add_argument("--expected-version", type=int, required=True)
    s = sub.add_parser("status"); s.add_argument("--site", required=True)
    d = sub.add_parser("remove"); d.add_argument("--site", required=True)
    sub.add_parser("reconcile")
    ns = p.parse_args(argv)
    dep = build()
    try:
        if ns.cmd == "site-add":
            out = dep.register_site(ns.actor, {"site_id": ns.id, "name": ns.name, "hostname": ns.hostname, "origin_host": ns.origin_host,
                                               "origin_port": ns.origin_port, "origin_scheme": ns.scheme}, {"mode": ns.mode})
        elif ns.cmd == "set-mode":
            cur = dep.store.get_policy(ns.site, ns.expected_version)
            out = dep.set_policy(ns.actor, ns.site, {**cur["config"], "mode": ns.mode}, ns.expected_version)
        elif ns.cmd == "rollback": out = dep.rollback(ns.actor, ns.site, ns.to, ns.expected_version)
        elif ns.cmd == "status": out = dep.protection_state(ns.site)
        elif ns.cmd == "remove": dep.remove_site(ns.actor, ns.site); out = {"removed": ns.site}
        else: out = dep.reconcile(ns.actor)
        print(json.dumps(out, indent=2)); return 0
    except (ValidationError, ConflictError, NotFound, DeploymentError) as e:
        print(json.dumps({"error": type(e).__name__, "detail": str(e)}, indent=2)); return 2

if __name__ == "__main__":
    sys.exit(main())
