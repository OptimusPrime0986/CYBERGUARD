# CyberGuard

## Phase 1: traffic-processing harness (WRITTEN, NOT EXECUTED)
Authored without Docker access. Treat every Phase 1 acceptance criterion as UNVERIFIED until
`./run_tests.sh` passes on your machine and you keep `results/phase1-output.txt`.

    ./run_tests.sh          # builds, starts, runs tests/test_phase1.py
    docker compose down -v

- `docker-compose.yml`: origin (internal-only network) + three proxies: blocking :8081, detect-only :8082, off :8083 (127.0.0.1 only).
- `origin/`: test origin that logs every request that reaches it.
- `tests/test_phase1.py`: blocking = 403 + CRS rule family + 949110 + origin never saw it; detect = recorded + forwarded; off = forwarded, nothing recorded; benign set passes everywhere; origin not published; backend network internal.

Verify on first run: `CRS_IMAGE` tag exists (pin it); audit log path (`MODSEC_AUDIT_LOG_PATH`, default `/var/log/modsec_audit.log`) and JSON `"ruleId"` format; `MODSEC_RULE_ENGINE`/`MODSEC_AUDIT_ENGINE` behave as documented for your tag.
Limits: no TLS, rate limiting, auth, DB or dashboard; paranoia level 1 only; no OWASP Top 10 coverage claim.

---

# Phase 2: protection controls (controller + generated per-site config)

## Status
- **Executed:** 50 unit tests (`pytest tests/unit`), output in `results/phase2-unit-output.txt`. They exercise validation/SSRF rules, config rendering, versioning, rollback, concurrency, audit immutability and reconcile against a **FakeEngine** that mimics nginx semantics (running config changes only on reload).
- **NOT executed:** anything involving real NGINX/ModSecurity: `docker-compose.phase2.yml`, `proxy/agent.sh`, `FileAgentEngine`, the canary probe, and the generated nginx/ModSecurity syntax. Unit tests prove the control logic, not that nginx accepts the output.

## How a mode change works
validate input -> render new immutable `releases/<n>/` -> atomically repoint `active` -> `nginx -t` (running workers untouched) -> reload -> verify RUNNING state (state endpoint version/mode + canary request) -> record. Any failure repoints `active` to the last good release (and reloads + re-verifies it if the engine had already switched). Effective state in the DB changes only after verification. No Docker socket is used; the proxy-side agent can only run `nginx -t` / `nginx -s reload`.

## Run with the dashboard (after Phase 1 passes)
    cp .env.example .env            # then fill in CG_SECRET_KEY, CG_ADMIN_EMAIL, CG_ADMIN_PASSWORD, and pin CRS_IMAGE
    docker compose -f docker-compose.phase2.yml up -d --build
    open http://127.0.0.1:8088      # sign in, click "+ Add website"
Add the bundled test site with: ID `demo`, hostname `demo.localhost`, origin host `origin`, port `5000`, protocol `http`.
Test enforcement from a terminal (or any HTTP client) while you click the mode buttons:

    curl -s -o /dev/null -w "%{http_code}\n" -H "Host: demo.localhost" "http://127.0.0.1:8000/s?q=%3Cscript%3Ealert(1)%3C/script%3E"
    # Blocking -> 403.  Monitoring only / Disabled -> 200 (reaches the origin).
The CLI still works: `docker compose -f docker-compose.phase2.yml exec app python -m cyberguard.cli status --site demo`.

## Assumptions to verify on first real run
1. (RESOLVED on first real run) Per-site files must NOT re-include `setup.conf`: the image loads CRS globally, and a second include fails `nginx -t` with 'Rule id: 200000 is duplicated'. Per-site files now contain only overrides (`SecRuleEngine`, body limits). Still unverified: that a per-server `SecRuleEngine DetectionOnly` overrides the global `On` as intended.
2. `modsecurity on/off` and `modsecurity_rules_file` are valid per `server{}` in that image's NGINX build; `nginx -t` will tell you.
3. Image entrypoint is `/docker-entrypoint.sh`; the process user can write the shared `cgshared` volume (controller runs as uid 10002, so you may need matching volume ownership).
4. The ModSecurity hook runs before nginx-level handling for the `/__cg_canary` path so a blocking canary yields 403. If not, verification fails and deploys roll back (fail-safe, but you'd see it immediately).

## Known limitations (Phase 2)
- **Not exposed (engine support unproven):** per-site paranoia level and anomaly threshold. CRS reads them before rules load, so they need a per-site crs-setup, deferred rather than faked.
- Rule exclusions, rate limits, TLS termination, trusted-proxy config: not implemented yet.
- All sites share one nginx reload, so a bad change to one site fails the *deploy* for all (nothing is applied; others keep running on the last good release).
- Origin hostnames are checked against SSRF rules at registration; DNS can change later (rebinding). Mitigation (re-validate at reload / pin IPs) is not implemented.
- In non-blocking modes the canary request reaches the customer origin (inert payload, `/__cg_canary`).
- SQLite is used for state here; PostgreSQL arrives in Phase 5. CLI `--actor` is unauthenticated until Phase 3.
- `docker-compose.phase2.yml` exposes only :8000 on 127.0.0.1; no TLS.

---

# Phase 3 + 4: management API and dashboard

## Status
- **Executed here:** 63 unit tests (`pytest tests/unit`): auth, generic login errors, login rate limit, CSRF, roles, cross-tenant isolation (other owners get 404), analyst read-only + origin hidden, SSRF rejection through the API, 502 on failed deploy with last-good kept, 409 on stale version, rollback, server-side logout revocation, SPA serving + security headers. The React dashboard **compiles** (`npm run build`).
- **NOT executed:** the dashboard has never been rendered or clicked in a browser; the Docker build of `deploy/app.Dockerfile`; any run against real NGINX/ModSecurity.

## What the dashboard shows (all from real data)
Website list with effective mode and verification state, per-site protection control (disable asks for confirmation naming the site), live health check, policy version history with restore, administrative activity log, add/remove website and user management (admin), role-based UI (analysts are read-only and cannot see origin addresses).

## Deliberately NOT shown
Request counts, blocked/allowed charts, detections by category, attack events, latency: the WAF event-ingestion pipeline (Phase 5) does not exist, so the dashboard says so instead of inventing numbers. Notifications, rule exclusions, rate-limit settings and MFA are also not built.

## Auth limitations
Passwords are hashed (werkzeug scrypt). Sessions are server-side and revoked on logout, 8h expiry, CSRF header required on writes. Login limiting is in-memory per (IP, email), so it resets on restart and is per-process. No MFA. No TLS in the bundled compose: bind to localhost or put a TLS terminator in front.

---

# Demo site and attack lab
`origin/app.py` is now a deliberately **inert** demo site (never executes SQL, commands or file reads; it only reports that a request reached it, and logs it). Browsers get a page with an "Attack lab"; other clients get JSON as before (Phase 1 tests unaffected).
- In a browser: `http://demo.localhost:8000` (Chrome/Edge/Firefox resolve `*.localhost` automatically; otherwise add `127.0.0.1 demo.localhost` to your hosts file). Requires a site registered with hostname `demo.localhost`.
- From a terminal: `python3 tools/attack_lab.py`
After changing the origin code: `docker compose -f docker-compose.phase2.yml up -d --build origin`.
Executed here: page JS syntax check, origin behaviour, and the script against the origin **without** a firewall (all 9 requests allowed: the baseline). Not executed: either tool through the real proxy.

---

# Event pipeline, demo bank/shop, redesigned dashboard

## Status
- **Executed here:** 85 unit tests: event parsing/redaction/de-duplication/restart/rotation/filters/ownership, and a baseline proving the bank and shop ARE vulnerable with no firewall in front (login bypass, UNION data theft, reflected/stored XSS, traversal into a fake file dict, IDOR, price/negative-amount flaws). The dashboard compiles, and the full React app was rendered in a simulated browser (jsdom) against real API responses and clicked through overview → site → events → event detail.
- **NOT executed (needs your Docker run):** everything that depends on the real proxy's log formats. These are my assumptions, listed so a failure is easy to locate:
  1. ModSecurity's JSON audit log has `transaction.unique_id`, `request.uri`, `request.headers`, `response.http_code`, and `messages[].details.{ruleId,severity,tags,data}`, written to `/var/log/modsec_audit.log`.
  2. `modsecurity_transaction_id "$request_id";` is accepted by this image's connector (if not, `nginx -t` fails and Add website shows a validation error naming it).
  3. The agent (runs as root in the proxy) can read those logs and write `/etc/cyberguard/logs/*.jsonl`.
  4. CRS rule 949110 is what turns a match into a 403, and detection-only events are still written to the audit log.
- If the Overview says **Event pipeline: waiting**, run:
  `docker compose -f docker-compose.phase2.yml exec proxy sh -c "ls -la /var/log/nginx /var/log/modsec_audit.log /etc/cyberguard/logs; tail -n 2 /var/log/nginx/cyberguard.jsonl; tail -c 500 /var/log/modsec_audit.log"` and send me the output.

## What the numbers mean
Requests/allowed/blocked/rejected come from the NGINX access log (blocked = 403 with no origin contact; rejected = 400/405/413/414/431 with no origin contact). Detected-not-blocked and all event details come from ModSecurity's audit log. Counts are WAF **events**, not unique attacks. Health-check canaries and unknown hostnames are excluded. Severity mapping: ModSecurity 0-2 → critical, 3 → high, 4 → medium, 5 → low, 6-7 → informational. Retention 30 days (`CG_RETENTION_DAYS`). Request bodies are never stored; query values for parameters named like password/token/key/card/session are redacted; control characters are stripped.

## Pipeline limits
Not guaranteed delivery: lines can be lost if the proxy host dies before the agent copies them, or around log rotation (shipped files are capped at ~50 MB then rotated once). Single-process ingestor. No alerting or notifications. No per-rule exclusions yet.

## Demo: attack the bank
1. Register ZenithBank and ShopEasy (quick-fill buttons in Add website). Open `http://bank.localhost:8000`, sign in `alice / alice123`, open **Attack guide**.
2. Set the site to **Disabled**, click each attack link: they succeed (data leaks, scripts run).
3. Set **Blocking**, repeat: the injection, XSS and traversal rows return 403; **IDOR and transfer flaws still work**, and that is the lesson: a WAF is one layer, not the application's access control.
4. Set **Monitoring only**: attacks succeed but appear in the Events tab as "detected".
5. Watch Overview/Traffic update every 5 seconds. Reset the sites with the footer button between runs.
Both sites are training apps with fake data and deliberate flaws. Never expose them to the internet. See `docs/FIREWALL_SETUP.md` for placing the firewall in front of a real site.

---

# Upgrade: hardening, alerts, HTTPS, two-factor, coverage

## Status
- **Executed here:** 156 unit tests (`pytest tests/unit`) and a simulated-browser run (jsdom) of the dashboard against real API responses for every new screen. The new unit tests cover policy validation (including rejection of unscoped/unsafe exclusions), config rendering, server-stamped exclusion authorship and expiry, certificate validation, TOTP (matches the RFC 6238 test vector, replay refused, secrets encrypted), alert thresholds / de-duplication / cooldown / failure recording / no-payload messages, scanner findings, coverage verdict logic, a database migration from the old schema, and per-owner access control on every new endpoint.
- **NOT executed:** none of the generated NGINX/ModSecurity config has run on a real proxy. See `docs/UPGRADE_CHECKS.md` (copy-paste checks) and the assumptions below.

## What was added
| Area | What it does | OWASP 2025 |
|---|---|---|
| Rate limits | Per-IP limits per path (429 + Retry-After); work even when the firewall is disabled; dry-run in Monitoring | A07, A06 |
| Sensitivity | Per-site anomaly threshold and paranoia level | A05 |
| Rule exclusions | Narrow (path and/or parameter), reason required, expiry, server-stamped author, auto-expire | A05 |
| Hardening | Security headers, hidden version banner, generic error pages, optional response-leak inspection | A02, A10 |
| HTTPS | Certificate install (PEM or self-signed), TLS 1.2/1.3, redirect, HSTS, trusted-proxy real-IP | A04 |
| Scanner | Configuration findings with fixes, kept separate from attack events | A02, A04 |
| Alerts | Email with thresholds, cooldown, delivery log; local inbox bundled (Mailpit) | A09 |
| Two-factor | TOTP for dashboard users; admin reset | A07 |
| Coverage page | OWASP 2025 table whose status comes only from tests run on the live proxy | all |

## Assumptions not yet proven on a real proxy
1. A phase-1 `SecAction` in the per-site file overrides `tx.inbound_anomaly_score_threshold` before CRS rule 949110 (phase 2) reads it. Paranoia overrides are best-effort (phase-2 rules only).
2. `ctl:ruleRemoveById` / `ruleRemoveTargetById` from a phase-1 rule in the per-site file suppress CRS phase-2 rules (the usual exclusion pattern). Exclusions of phase-1 rules may not take effect.
3. `limit_req_zone` in `05-ratelimit.conf` plus per-location `limit_req`, `limit_req_status 429`, `limit_req_dry_run`, and `error_page 429 @named` behave as written.
4. `proxy_intercept_errors on` with named `error_page` locations replaces origin 5xx bodies; `SecResponseBodyAccess On` works with the image's default response mime types.
5. `ssl_session_cache shared:cg_ssl:10m` repeated per server block, a default TLS server with a real cert, and `set_real_ip_from` (needs the realip module) are accepted by this NGINX build.
6. `cryptography==46.0.6` installs in the app image; `axllent/mailpit:latest` starts (pin a tag in `.env` via `MAILPIT_IMAGE`).
If Add website / Save policy fails, the error names the directive; send it and I will adjust.

## Found on the first real run
- `server_tokens` was already set by the image's `conf.d/default.conf`; my duplicate made `nginx -t` fail ("directive is duplicate"). Removed; the version banner now relies on the image default, and the Security checks scan verifies it.

## Known limits (unchanged honesty)
- A WAF cannot prevent or fully detect any of the OWASP ten; A03 (supply chain) is outside its reach and access-control/business-logic flaws stay invisible to it (the demo sites show this).
- Rate limits are per IP (shared addresses share a limit; attackers can spread); no account lockout by design. Zones use 2 MB each (max 5 per site).
- Certificate renewal is manual; no ACME. HSTS preload not offered.
- Two-factor has no recovery codes and no QR code (enter the key manually).
- Alert delivery is best-effort; a down mail server is recorded, not retried until the next cooldown.
- Event delivery is not guaranteed across proxy-host failure (see Pipeline limits above).
- CyberGuard's own headers replace the website's for the four standard security headers; no automatic CSP (a wrong CSP breaks sites).
- Webhook alerts, per-account rate limits and ACME are not built.

---

# Console redesign
Sidebar navigation; websites as a dense list with the protection mode as a coloured edge on each row; metrics in one strip; the protection control as a three-position switch (Blocking / Monitoring only / Disabled) with the current mode filled in its signal colour; split sign-in page; sentence-case copy; light and dark themes. Signal colours always mean the same thing (green protected, amber monitoring, red disabled or blocked, purple rate-limited); normal traffic uses a calm blue-grey so alarming colours stand out.
Fonts (Instrument Sans, JetBrains Mono for rule ids and paths) are bundled into the app, so there are no external requests and the Content-Security-Policy stays strict.
**Verified:** the dashboard builds; the whole app renders in a simulated browser (jsdom) and every screen was clicked through; palette contrast was computed (all text pairs meet WCAG AA 4.5:1 in light and dark; hint text darkened to pass). **Not verified:** how it looks in a real browser. I could not take screenshots here, so spacing and visual balance are untested by eye. Tell me what looks off and I will adjust.
