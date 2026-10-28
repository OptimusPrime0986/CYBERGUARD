"""Shared helpers for the deliberately vulnerable TRAINING sites (bank, shop). Fake data only."""
import json, os, threading, time
from flask import request
from markupsafe import escape as esc

LOG = os.environ.get("CG_ORIGIN_LOG", "/data/requests.jsonl")
_lock = threading.Lock()


def log_request():
    """Record every request that actually reaches the site (proof of 'did it get through the firewall?')."""
    e = {"ts": time.time(), "method": request.method, "path": request.path, "query": request.query_string.decode("utf-8", "replace"),
         "test_id": request.headers.get("X-Test-Id"), "body_len": len(request.get_data())}
    with _lock, open(LOG, "a") as f:
        f.write(json.dumps(e) + "\n")


def money(v):
    try: return "${:,.2f}".format(float(v))
    except (TypeError, ValueError): return str(esc(v))      # injected UNION rows put text in numeric columns: show it, don't crash


CSS = """
:root{--a:@@A@@;--bg:#f4f6fa;--c:#fff;--t:#16202e;--m:#667085;--l:#e2e6ee}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--t)}
.warn{background:#7a1f1f;color:#fff;text-align:center;padding:6px 10px;font-size:12.5px}
header{background:var(--a);color:#fff;padding:0 24px;display:flex;align-items:center;gap:28px;flex-wrap:wrap}
header b{font-size:20px;padding:14px 0}header a{color:#fff;text-decoration:none;opacity:.9;padding:16px 0;font-size:14px}header a:hover{opacity:1;text-decoration:underline}
main{max-width:980px;margin:0 auto;padding:24px}.hero{background:linear-gradient(120deg,var(--a),#0b1b3a);color:#fff;border-radius:14px;padding:44px 32px;margin-bottom:24px}
.hero h1{margin:0 0 8px;font-size:32px}.hero p{opacity:.9;max-width:560px}
.card{background:var(--c);border:1px solid var(--l);border-radius:12px;padding:18px;margin-bottom:16px}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}h2{margin:0 0 10px;font-size:18px}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--l)}
input,select,textarea{font:inherit;padding:9px;border:1px solid #c9cfdb;border-radius:8px;width:100%;margin:4px 0 12px}
button,.btn{font:inherit;background:var(--a);color:#fff;border:0;border-radius:8px;padding:10px 18px;cursor:pointer;text-decoration:none;display:inline-block}
.btn.o{background:#fff;color:var(--a);border:1px solid var(--a)}.err{background:#fde8e8;color:#8a1c1c;padding:10px;border-radius:8px;margin-bottom:12px;word-break:break-word}
.ok{background:#e4f6ea;color:#14633a;padding:10px;border-radius:8px;margin-bottom:12px}.big{font-size:26px;font-weight:700}.muted{color:var(--m);font-size:13px}
footer{text-align:center;color:var(--m);font-size:12.5px;padding:24px}pre{background:#0e1624;color:#d6e2f5;padding:12px;border-radius:8px;overflow:auto;font-size:13px}
.tag{display:inline-block;background:#eef2fb;border-radius:99px;padding:1px 10px;font-size:12px}
"""


def shell(brand, accent, nav, title, body, user=None):
    """Page chrome. `body` is HTML supplied by the caller (callers escape safe values with esc(); vulnerable spots do not)."""
    links = "".join(f'<a href="{u}">{esc(t)}</a>' for t, u in nav)
    who = f'<span style="margin-left:auto;font-size:13px">{esc(user)} · <a href="/logout" style="padding:0">Sign out</a></span>' if user else '<a href="/login" style="margin-left:auto">Sign in</a>'
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(title)} · {esc(brand)}</title><style>{CSS.replace("@@A@@", accent)}</style></head><body>'
            f'<div class="warn">TRAINING SITE: deliberately vulnerable, fake data only. Never expose it to the internet. It exists to test the CyberGuard firewall.</div>'
            f'<header><b>{esc(brand)}</b>{links}{who}</header><main>{body}</main>'
            f'<footer>{esc(brand)} is a fictional demo. <form method="post" action="/__reset" style="display:inline"><button class="btn o" style="padding:3px 10px;font-size:12px">Reset demo data</button></form></footer></body></html>')


def guide(rows, intro):
    """Attack guide page. rows: (name, category, url, without_firewall, with_firewall)"""
    tr = "".join(f'<tr><td><b>{esc(n)}</b><br><span class="tag">{esc(c)}</span></td><td><a href="{esc(u)}"><code>{esc(u)}</code></a></td><td>{esc(a)}</td><td>{esc(b)}</td></tr>' for n, c, u, a, b in rows)
    return (f'<div class="card"><h2>Attack guide</h2><p>{intro}</p>'
            '<p class="muted">Sign in first where a row says so. Click a link to send the attack; compare results with the firewall in <b>Blocking</b>, <b>Monitoring only</b> and <b>Disabled</b> mode. '
            'Use "Reset demo data" in the footer between runs.</p></div>'
            f'<div class="card" style="overflow:auto"><table><thead><tr><th>Attack</th><th>Request</th><th>Without firewall</th><th>Firewall blocking</th></tr></thead><tbody>{tr}</tbody></table></div>')
