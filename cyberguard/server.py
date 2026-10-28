"""Production entrypoint: gunicorn cyberguard.server:app. Fails loudly if required secrets are missing."""
import os, threading, time
from werkzeug.security import generate_password_hash
from .alerts import AlertEngine, smtp_sender
from .api import create_app
from .cli import build
from .events import Ingestor


def _forever(fn, every):
    def loop():
        while True:
            try: fn()
            except Exception: pass                       # a failing job must never take the API down; failures surface on the dashboard
            time.sleep(every)
    threading.Thread(target=loop, daemon=True).start()


def make_app():
    secret, email, pw = os.environ.get("CG_SECRET_KEY", ""), os.environ.get("CG_ADMIN_EMAIL", ""), os.environ.get("CG_ADMIN_PASSWORD", "")
    if len(secret) < 32: raise RuntimeError("CG_SECRET_KEY must be set (>= 32 chars)")
    dep = build()
    if not dep.store.list_users():
        if not email or len(pw) < 12: raise RuntimeError("First start needs CG_ADMIN_EMAIL and CG_ADMIN_PASSWORD (>= 12 chars)")
        dep.store.create_user(email.lower(), generate_password_hash(pw), "admin")
    if os.environ.get("CG_LOG_DIR"):
        Ingestor(dep.store, os.environ["CG_LOG_DIR"], retention_days=int(os.environ.get("CG_RETENTION_DAYS", "30"))).start()
    ae = AlertEngine(dep.store, smtp_sender())
    _forever(ae.run_once, 30)
    _forever(lambda: dep.expire_exclusions("system"), 3600)
    return create_app(dep, secret, os.environ.get("CG_COOKIE_SECURE", "true").lower() != "false", os.environ.get("CG_STATIC_DIR"), alert_engine=ae)


app = make_app() if os.environ.get("CG_SECRET_KEY") else None
