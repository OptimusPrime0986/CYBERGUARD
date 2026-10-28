"""Configuration scanner (A02/A04/A10 hygiene). Findings describe how a site is CONFIGURED; they are not attack detections
and are reported separately. Probes are harmless GETs sent through the proxy, exactly as a visitor would."""
import re
from datetime import datetime, timezone

SENSITIVE = ("/.git/config", "/.env", "/server-status", "/phpinfo.php")
AUTHISH = re.compile(r"login|signin|sign-in|auth|password|reset|register|signup", re.I)


def scan(site, policy, fetch, tls_status, today=None):
    out = []
    def add(id, title, status, sev, owasp, detail, fix=""): out.append({"id": id, "title": title, "status": status, "severity": sev, "owasp": owasp, "detail": detail, "fix": fix})
    status, h, _ = fetch("/")
    if status == 0:
        return {"error": "The site could not be reached through the proxy, so response checks were skipped.", "findings": [], "summary": {}}
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # --- response headers ---
    def hdr(id, title, ok, sev, why, fix):
        add(id, title, "pass" if ok else "fail", sev, "A02", "Present." if ok else why, "" if ok else fix)
    hdr("hdr-nosniff", "X-Content-Type-Options", h.get("x-content-type-options", "").lower() == "nosniff", "medium", "Browsers may guess content types.", "Enable 'Security headers' in the policy.")
    hdr("hdr-frame", "Clickjacking protection", bool(h.get("x-frame-options")) or "frame-ancestors" in h.get("content-security-policy", ""), "medium", "The site can be embedded in other sites' frames.", "Enable 'Security headers' in the policy.")
    hdr("hdr-referrer", "Referrer-Policy", bool(h.get("referrer-policy")), "low", "Full URLs may leak to other sites.", "Enable 'Security headers' in the policy.")
    hdr("hdr-permissions", "Permissions-Policy", bool(h.get("permissions-policy")), "low", "Powerful browser features are not restricted.", "Enable 'Security headers' in the policy.")
    csp = bool(h.get("content-security-policy"))
    add("hdr-csp", "Content-Security-Policy", "pass" if csp else "warn", "medium", "A02", "Present." if csp else "Not set. CyberGuard does not add one automatically because a wrong policy breaks sites.", "" if csp else "Have the application send a CSP, starting in report-only mode.")
    srv, pw = h.get("server", ""), h.get("x-powered-by")
    leaks = [x for x in (srv if re.search(r"\d+\.\d+", srv) else "", f"X-Powered-By: {pw}" if pw else "") if x]
    add("banner", "Software version disclosure", "fail" if leaks else "pass", "low", "A02", ("Reveals: " + "; ".join(leaks)) if leaks else "No version information in headers.", "Remove or hide the Server/X-Powered-By headers." if leaks else "")

    # --- exposed sensitive files (the probe goes through the WAF, so a block counts as protected) ---
    exposed = [p for p in SENSITIVE if fetch(p)[0] == 200]
    add("sensitive-files", "Exposed sensitive files", "fail" if exposed else "pass", "high", "A02",
        ("Readable without authentication: " + ", ".join(exposed)) if exposed else "None of the common sensitive paths were readable.",
        "Remove the files from the web root; do not rely on the firewall alone." if exposed else "")

    # --- transport (A04) ---
    if policy.https == "off":
        add("https", "HTTPS", "fail", "high", "A04", "Visitors reach this site over plain HTTP through the firewall.", "Install a certificate and set HTTPS to 'redirect'.")
    else:
        add("https", "HTTPS", "pass" if policy.https == "redirect" else "warn", "medium", "A04", f"HTTPS mode: {policy.https}.", "" if policy.https == "redirect" else "Use 'redirect' so HTTP visitors are sent to HTTPS.")
        add("hsts", "HSTS", "pass" if policy.hsts else "warn", "medium", "A04", "Enabled." if policy.hsts else "Not enabled.", "" if policy.hsts else "Enable HSTS once HTTPS works for all visitors.")
        if tls_status.get("installed"):
            left = tls_status["days_left"]
            add("cert", "Certificate", "warn" if (tls_status["self_signed"] or left < 14) else "pass", "medium", "A04",
                f"{'Self-signed. ' if tls_status['self_signed'] else ''}Expires in {left} days.", "Install a certificate from a trusted authority and renew before expiry." if (tls_status["self_signed"] or left < 14) else "")

    # --- CyberGuard configuration ---
    add("mode", "Firewall mode", {"blocking": "pass", "monitoring": "warn", "disabled": "fail"}[policy.mode], "high" if policy.mode == "disabled" else "medium", "A05",
        {"blocking": "Blocking attacks.", "monitoring": "Attacks are detected but not blocked.", "disabled": "The firewall is not inspecting this site."}[policy.mode], "" if policy.mode == "blocking" else "Switch to Blocking once false positives are resolved.")
    add("errors", "Generic error pages", "pass" if policy.generic_errors else "warn", "medium", "A10", "Origin 5xx pages are replaced with a plain message." if policy.generic_errors else "Origin error pages (possibly stack traces) reach visitors.", "" if policy.generic_errors else "Enable 'Generic error pages'.")
    add("threshold", "Blocking threshold", "pass" if policy.anomaly_threshold <= 5 else "warn", "medium", "A05", f"Anomaly threshold {policy.anomaly_threshold} (default 5).", "" if policy.anomaly_threshold <= 5 else "A higher threshold lets weaker matches through.")
    ex = policy.exclusions
    expired = [e["rule_id"] for e in ex if e.get("expires") and e["expires"] < today]
    broad = [e["rule_id"] for e in ex if not e.get("path")]
    add("exclusions", "Rule exclusions", "warn" if (expired or broad) else ("pass" if ex else "info"), "medium", "A05",
        f"{len(ex)} active." + (f" Expired but still listed: {', '.join(expired)}." if expired else "") + (f" Not limited to a path: {', '.join(broad)}." if broad else ""), "Remove stale exclusions and scope each to a path." if (expired or broad) else "")
    rl = policy.rate_limits
    auth_covered = any(AUTHISH.search(r["path"]) for r in rl)
    add("ratelimit", "Rate limiting", "pass" if auth_covered else ("info" if rl else "warn"), "medium", "A07",
        "A rate limit covers a sign-in style path." if auth_covered else (f"{len(rl)} rule(s), none on a sign-in/reset path." if rl else "No rate limits: password guessing is not slowed down."),
        "" if auth_covered else "Add a limit on your login, reset and registration paths.")
    summary = {k: sum(1 for f in out if f["status"] == k) for k in ("pass", "fail", "warn", "info")}
    return {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "findings": out, "summary": summary,
            "note": "Configuration findings, separate from attack detections."}
