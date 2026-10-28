# How to place CyberGuard between visitors and a website

## The idea
```
Visitor ──► DNS (your domain → CyberGuard's address)
              │
              ▼
        ┌─────────────────────────────────────────┐
        │ CyberGuard server                       │
        │  NGINX proxy (:8000)                    │
        │    ├─ ModSecurity + OWASP CRS inspects  │
        │    │   the request                      │
        │    ├─ attack?  ──► 403 (never forwarded)│
        │    └─ clean?   ──► forwards to ─────────┼──► Your website (origin)
        │  Logs ► event pipeline ► dashboard      │        │
        │  Dashboard/API (:8088, you only)        │        ▼
        └─────────────────────────────────────────┘     its database
```
The website must only be reachable **through** CyberGuard. If visitors (or attackers) can still reach the website's own address directly, the firewall is bypassed.

## What happens to one request
1. The visitor's browser resolves `www.example.com` and connects to CyberGuard's proxy.
2. NGINX picks the site by the `Host` name; unknown names are dropped.
3. Method and body-size limits are checked (405/413 if exceeded).
4. ModSecurity scores the request against the OWASP rules (query, headers, cookies, body).
5. **Blocking mode:** score over threshold → 403, the website never sees it. **Monitoring only:** the match is logged, the request is forwarded. **Disabled:** no inspection, request forwarded.
6. Clean requests are forwarded to the origin; its response goes back through the proxy.
7. The proxy writes an access-log line (and an audit-log entry if a rule matched). The agent copies both to a shared volume, the ingestor stores them, and the dashboard shows them within a few seconds.

## A. Local demo (bank and shop)
1. Start the stack (README → "Run with the dashboard"). Sign in at `http://127.0.0.1:8088`.
2. **+ Add website** → click the **ZenithBank demo** quick-fill → **Add and verify**. Repeat with **ShopEasy demo**.
3. Open `http://bank.localhost:8000` (Chrome/Edge/Firefox resolve `*.localhost` automatically; otherwise add `127.0.0.1 bank.localhost shop.localhost` to your hosts file).
4. The demo site "origin" is the container named `origin` on port 5000. It sits on an internal Docker network with no published port, so the **only** way in is through the proxy on port 8000.

## B. A real website (checklist)
Do these in order. Items marked **NOT BUILT** are real gaps in this version.

1. **Run CyberGuard on a server with a public IP.** Use `docker compose -f docker-compose.phase2.yml up -d --build`. Keep the dashboard port (8088) private (VPN, SSH tunnel or firewall rule); never publish it openly.
2. **Register the site** in the dashboard:
   - *Public hostname*: your domain, e.g. `www.example.com`.
   - *Origin host / port / protocol*: where the site really runs, e.g. `203.0.113.10`, `443`, `https`. Upstream TLS certificates are verified by default.
   - Origins on private/loopback/cloud-metadata addresses are refused. If your origin legitimately lives on a private network, an administrator must allow it via `CG_ALLOWED_ORIGIN_HOSTS` / `CG_ALLOWED_ORIGIN_CIDRS` in the compose file.
3. **Lock the origin so only CyberGuard can reach it.** In your cloud security group or host firewall, allow the origin's port **only from CyberGuard's IP**. Without this, anyone who learns the origin's IP skips the firewall entirely. This step is outside CyberGuard and is the most commonly missed one.
4. **Start in Monitoring only.** Run for a few days, read the Events tab, and look for legitimate traffic being flagged (false positives). When a rule flags real users, open the site's **Policy** tab and add a narrow **rule exclusion** (a path and/or a parameter, with a reason and an expiry date). Do not turn a rule off for the whole site.
   Also on the Policy tab: **rate limits** on your login/reset/checkout paths, security headers, generic error pages, and detection sensitivity. Run **Security checks** and fix what it reports.
5. **Test before switching DNS.** Send requests to the proxy with the site's name, e.g. `curl -H "Host: www.example.com" http://<cyberguard-ip>:8000/`.
6. **Cut over DNS.** Lower the record's TTL a day earlier, then point `www.example.com` at CyberGuard's IP. To roll back, point it back at the origin.
7. **HTTPS.** On the site's Policy tab an administrator installs a certificate (paste a PEM pair, or generate a self-signed one for testing), then sets HTTPS to *Redirect* and, once it works everywhere, turns on HSTS. TLS 1.2/1.3 only. The proxy serves HTTPS on port 8443 in this setup; map 443 to it in production and set `CG_PUBLIC_HTTPS_PORT=443`.
   **Certificate renewal is manual** (no ACME/Let's Encrypt automation): install the new certificate before the old one expires; the scanner warns below 14 days.
   **Behind your own load balancer/TLS terminator?** Set `CG_TRUSTED_PROXIES` to its address range so the real visitor IP is used for rate limits and events. Only addresses you list are believed; anyone else's `X-Forwarded-For` is ignored.
8. **Switch to Blocking** once Monitoring shows no legitimate traffic being flagged. Watch the Overview for rejected or blocked spikes right after.
9. **Operate:** back up the `cgdata` and `cgshared` Docker volumes; pin and test image updates before applying; turn on **two-factor sign-in** for every administrator (Account page) and set up **email alerts** per site (Alerts tab; point `CG_SMTP_*` at a real mail server). There are no recovery codes: an administrator resets a lost device.

## What a WAF does not fix
It cannot know who is allowed to see which record (broken access control), cannot spot flawed business logic (negative transfers, price tampering), and cannot fix weak passwords or vulnerable libraries. The demo sites include examples of each, marked "NOT blocked" in their attack guides, on purpose.
