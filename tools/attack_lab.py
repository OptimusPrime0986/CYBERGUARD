#!/usr/bin/env python3
"""Send harmless, well-known attack strings through your CyberGuard proxy and report what happened.
Only run against YOUR OWN test setup. Needs Python 3, no extra packages.

  python3 tools/attack_lab.py                       # defaults: http://127.0.0.1:8000, Host demo.localhost
  python3 tools/attack_lab.py --host other.example  # a different registered hostname
"""
import argparse, sys, urllib.error, urllib.parse, urllib.request

TESTS = [  # (name, is_attack, path, value)
    ("SQL injection: tautology", True, "/search?q=", "' OR '1'='1"),
    ("SQL injection: UNION SELECT", True, "/search?q=", "1 UNION SELECT username,password FROM users--"),
    ("XSS: script tag", True, "/comment?text=", "<script>alert(1)</script>"),
    ("XSS: img onerror", True, "/comment?text=", "<img src=x onerror=alert(1)>"),
    ("Path traversal", True, "/download?file=", "../../../../etc/passwd"),
    ("Command injection", True, "/ping?host=", "127.0.0.1; cat /etc/passwd"),
    ("Normal: SQL-ish words", False, "/search?q=", "how to select a good union rep"),
    ("Normal: plain text", False, "/comment?text=", "Great product, five stars"),
    ("Normal: unicode", False, "/search?q=", "caf\u00e9 \u6771\u4eac"),
]


def fetch(url, host):
    req = urllib.request.Request(url, headers={"Host": host, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000"); ap.add_argument("--host", default="demo.localhost")
    a = ap.parse_args()
    blocked = attacks = fp = errors = 0
    print(f"Target {a.url}  (Host: {a.host})\n")
    print(f"{'TEST':34} {'RESULT':32} NOTE")
    for name, attack, path, val in TESTS:
        st, body = fetch(a.url + path + urllib.parse.quote(val, safe=""), a.host)
        reached = st == 200 and '"reached_origin"' in body
        if st == 403: res = "BLOCKED by WAF (403)"
        elif reached: res = "ALLOWED (reached site)"
        else: res = f"OTHER (HTTP {st})"; errors += 1
        note = ""
        if attack:
            attacks += 1; blocked += st == 403
            note = "" if st == 403 else "<- not blocked"
        elif st == 403: fp += 1; note = "<- FALSE POSITIVE"
        print(f"{name:34} {res:32} {note}")
    print(f"\n{blocked} of {attacks} attacks blocked; {fp} normal requests wrongly blocked; {errors} unexpected responses.")
    if errors: print("Unexpected responses usually mean the site/hostname isn't registered or the proxy is down.")
    print("Blocking mode should block attacks. Monitoring only / Disabled should block none.")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
