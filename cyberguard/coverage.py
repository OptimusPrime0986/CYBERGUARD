"""OWASP Top 10:2025 coverage registry. Static claims describe design; the STATUS column comes only from tests actually run
against the live proxy (stored with a timestamp). Nothing is 'protected' because a ruleset is installed."""
import time
from datetime import datetime, timezone

from .scanner import scan

REGISTRY = [
 {"id": "A01", "name": "Broken Access Control", "tests": ["A01-traversal", "A01-restricted-file", "A01-idor"],
  "prevent": "Path traversal and requests for restricted files (.git, .env).", "detect": "Same, as events.",
  "app_level": "Who may see which record. A WAF cannot know ownership: fix in application code.", "limits": "IDOR/forced browsing of normal URLs is invisible to a WAF."},
 {"id": "A02", "name": "Security Misconfiguration", "tests": ["A02-headers", "A02-banner", "A02-sensitive-files"],
  "prevent": "Adds security headers, hides version banners, blocks restricted-file probes.", "detect": "Configuration scanner reports gaps.",
  "app_level": "Insecure defaults inside the application, cloud settings and credentials.", "limits": "Only what is visible in responses is checked."},
 {"id": "A03", "name": "Software Supply Chain Failures", "tests": [], "prevent": "None.", "detect": "None.",
  "app_level": "Dependency scanning, locked builds, signed artifacts.", "limits": "Not visible in HTTP traffic: outside what a WAF can do."},
 {"id": "A04", "name": "Cryptographic Failures", "tests": ["A04-https"],
  "prevent": "TLS 1.2+/1.3 termination, HTTP-to-HTTPS redirect, HSTS.", "detect": "Scanner flags plain HTTP and weak/self-signed/expiring certificates.",
  "app_level": "Weak hashing or encryption of stored data.", "limits": "Cannot see data at rest."},
 {"id": "A05", "name": "Injection", "tests": ["A05-sqli-union", "A05-xss", "A05-sqli-numeric", "A05-cmdi"],
  "prevent": "OWASP CRS blocks common SQLi, XSS, command and file injection; sensitivity and exclusions are adjustable per site.",
  "detect": "Every match is an event with rule, severity and policy version.", "app_level": "Parameterised queries and output encoding.",
  "limits": "Evasion of rules is possible; the vulnerable code remains."},
 {"id": "A06", "name": "Insecure Design", "tests": [], "prevent": "Rate limits slow scripted abuse of sensitive routes.", "detect": "Rate-limit events.",
  "app_level": "Business logic (negative transfers, price tampering).", "limits": "Logic flaws look like normal requests."},
 {"id": "A07", "name": "Authentication Failures", "tests": ["A07-ratelimit"],
  "prevent": "Injection-based login bypass; per-IP rate limiting of login/reset paths; TOTP two-factor for the CyberGuard console.",
  "detect": "Rate-limit counts and alerts.", "app_level": "Password policy, session handling, the application's own MFA.",
  "limits": "Per-IP limits can be spread across addresses; no account lockout by design."},
 {"id": "A08", "name": "Software or Data Integrity Failures", "tests": [], "prevent": "Some known exploit payloads match CRS rules.", "detect": "Same.",
  "app_level": "Verifying code, updates and serialized data.", "limits": "A WAF cannot verify provenance."},
 {"id": "A09", "name": "Security Logging and Alerting Failures", "tests": ["A09-events"],
  "prevent": "n/a", "detect": "Every matched attack is logged; email alerts with de-duplication.", "app_level": "The application's own logging and monitoring.",
  "limits": "Only requests the firewall sees. Event delivery is not guaranteed across proxy-host failure."},
 {"id": "A10", "name": "Mishandling of Exceptional Conditions", "tests": ["A10-errors"],
  "prevent": "Rejects malformed/oversized requests; replaces origin 5xx pages with a generic message.", "detect": "Optional response leak rules.",
  "app_level": "Error handling inside the application.", "limits": "Errors returned as HTTP 200 pages are not intercepted."},
]
NO_FIND = "Register the demo sites (ZenithBank as bank.localhost and ShopEasy as shop.localhost) to run these tests."


def verdict(cat, results):
    if not cat["tests"]: return "no_waf_control"
    st = [results[t]["status"] for t in cat["tests"] if t in results]
    if not st: return "not_tested"
    if "fail" in st: return "failed"
    if all(s == "pass" for s in st): return "verified"
    if "pass" in st: return "partial"
    return "not_verified"          # everything skipped / not configured / known gap


def run_tests(store, dep, probe, sleep=time.sleep, wait_events=8):
    sites = {c["site_id"]: c for c in store.list_sites()}
    pick = lambda pre: next((c for c in sites.values() if c["hostname"].startswith(pre)), None)
    bank, shop = pick("bank."), pick("shop.")
    if not bank and not shop: return {"error": NO_FIND, "results": {}}
    res, started = {}, datetime.now(timezone.utc).isoformat()

    def pol(c):
        st = store.get_state(c["site_id"]); return dep.policy_of(c["site_id"]) if st and st["effective_version"] else None
    def put(id, status, detail): res[id] = {"id": id, "status": status, "detail": detail}
    def need(c, id):
        if not c: put(id, "skipped", NO_FIND); return None
        return pol(c)
    def attack(id, c, path, what):
        p = need(c, id)
        if not p: return
        if p.mode != "blocking": return put(id, "skipped", f"Site is in '{p.mode}' mode: attacks are not blocked by design. Re-run in Blocking mode.")
        s, _, _ = probe(c["hostname"], path)
        put(id, "pass" if s == 403 else "fail", f"{what}: HTTP {s} ({'blocked by the firewall' if s == 403 else 'NOT blocked'}).")

    attack("A05-sqli-union", shop, "/search?q=%27%20UNION%20SELECT%20id%2Cusername%2Cpassword%2Crole%20FROM%20users--", "SQL injection (UNION)")
    attack("A05-xss", shop, "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "Cross-site scripting")
    attack("A05-sqli-numeric", shop, "/product?id=0%20UNION%20SELECT%201%2C2%2C3%2C4%2C5", "SQL injection (numeric)")
    attack("A05-cmdi", shop, "/search?q=x%3B%20cat%20%2Fetc%2Fpasswd", "Command injection")
    attack("A01-traversal", bank, "/statement?file=../../../etc/passwd", "Path traversal")
    attack("A01-restricted-file", shop, "/.git/config", "Restricted file probe")

    c = bank
    if not c: put("A01-idor", "skipped", NO_FIND)
    else:
        s, _, _ = probe(c["hostname"], "/account?id=3")
        put("A01-idor", "gap", f"HTTP {s}: the request is not blocked. Ownership checks must live in the application (confirmed limitation).")

    target = shop or bank
    p = pol(target) if target else None
    if p:
        sc = scan(target, p, lambda path: probe(target["hostname"], path), dep.tls_status(target["site_id"]))
        by = {f["id"]: f for f in sc.get("findings", [])}
        if sc.get("error"): put("A02-headers", "skipped", sc["error"]); put("A02-banner", "skipped", sc["error"]); put("A02-sensitive-files", "skipped", sc["error"])
        else:
            hd = [by[k] for k in ("hdr-nosniff", "hdr-frame", "hdr-referrer", "hdr-permissions")]
            put("A02-headers", "pass" if all(f["status"] == "pass" for f in hd) else "fail", "All standard security headers present." if all(f["status"] == "pass" for f in hd) else "Missing: " + ", ".join(f["title"] for f in hd if f["status"] != "pass"))
            put("A02-banner", by["banner"]["status"], by["banner"]["detail"])
            if p.mode == "blocking": put("A02-sensitive-files", by["sensitive-files"]["status"], by["sensitive-files"]["detail"])
            else: put("A02-sensitive-files", "skipped", f"Site is in '{p.mode}' mode; the scanner would only report what the origin exposes.")
        put("A04-https", "pass" if p.https != "off" and dep.tls_status(target["site_id"])["installed"] else "not_configured",
            f"HTTPS mode '{p.https}'." if p.https != "off" else "HTTPS is not enabled for this site.")
    else:
        for i in ("A02-headers", "A02-banner", "A02-sensitive-files", "A04-https"): put(i, "skipped", NO_FIND)

    rl_site = next((c for c in (shop, bank) if c and pol(c) and pol(c).rate_limits), None)
    if not rl_site: put("A07-ratelimit", "not_configured", "No rate limit is configured on the demo sites.")
    else:
        pp = pol(rl_site); rule = pp.rate_limits[0]
        if pp.mode == "monitoring": put("A07-ratelimit", "skipped", "Monitoring mode evaluates limits without enforcing them (dry run).")
        else:
            codes = [probe(rl_site["hostname"], rule["path"])[0] for _ in range(min(rule["burst"] + 12, 80))]
            put("A07-ratelimit", "pass" if 429 in codes else "fail", f"{len(codes)} rapid requests to {rule['path']}: {codes.count(429)} were rate-limited (HTTP 429).")

    if not bank: put("A10-errors", "skipped", NO_FIND)
    else:
        pb = pol(bank); s, _, body = probe(bank["hostname"], "/report?id=abc")
        leak = "Traceback" in body
        put("A10-errors", ("fail" if leak else "pass") if pb.generic_errors else "not_configured",
            (f"HTTP {s}: " + ("stack trace reached the visitor." if leak else "visitor saw a generic message.")) if pb.generic_errors else "Generic error pages are off for this site.")

    pe = pol(shop or bank)
    if pe and pe.mode == "disabled": put("A09-events", "skipped", "Firewall is disabled; no events are expected.")
    elif pe and "A05-sqli-union" in res and res["A05-sqli-union"]["status"] in ("pass", "fail"):
        end, sid = time.time() + wait_events, (shop or bank)["site_id"]
        n = 0
        while time.time() < end:
            n = store._q("SELECT COUNT(*) n FROM waf_events WHERE site_id=? AND ts>=?", (sid, started))[0]["n"]
            if n: break
            sleep(1)
        put("A09-events", "pass" if n else "fail", f"{n} firewall event(s) recorded during this run." if n else "Attacks were sent but no event reached the dashboard (check the event pipeline).")
    else: put("A09-events", "skipped", "Needs a Blocking-mode run of the injection tests.")
    return {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "results": res,
            "modes": {k: pol(v).mode for k, v in (("bank", bank), ("shop", shop)) if v and pol(v)}}


def view(store):
    run = store.kv_get("coverage:last") or {"results": {}}
    cats = [{**c, "verdict": verdict(c, run["results"]), "test_results": [run["results"][t] for t in c["tests"] if t in run["results"]]} for c in REGISTRY]
    return {"categories": cats, "last_run": {k: run.get(k) for k in ("ts", "modes", "error")},
            "note": "Verdicts come only from tests run against the live proxy. 'verified' means the listed tests passed in the mode shown, not that the category is solved."}
