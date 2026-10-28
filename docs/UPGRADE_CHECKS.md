# Verify the new controls on your running stack (PowerShell)

Nothing below has been run against a real NGINX/ModSecurity yet; these checks tell you (and me) which of my assumptions hold.
Register the demo sites first (Add website → ZenithBank demo, ShopEasy demo). Use `curl.exe`, not `curl`.

## 1. Config deploys at all
Open a site → **Policy** tab → change nothing → **Save policy**. If it fails the red error names the rejected directive. Send it to me.

## 2. Rate limiting (A07/A06)
Policy tab on ShopEasy → **+ Add rate limit** (name `login`, path `/login`, 10/min, burst 3) → Save. Then:
```powershell
1..20 | ForEach-Object { curl.exe -s -o NUL -w "%{http_code} " -H "Host: shop.localhost" http://127.0.0.1:8000/login }
```
Expect `200`s (or 405/302 from the app) then `429`. In Monitoring mode you should see no 429s (dry run). Overview shows the **Rate limited** counter rising.

## 3. Security headers, banner (A02)
```powershell
curl.exe -s -D - -o NUL -H "Host: shop.localhost" http://127.0.0.1:8000/
```
Expect `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`; no `Server: nginx/1.x.x` version and no `X-Powered-By`. Then site → **Security checks → Run scan now**.

## 4. Exposed file and restricted-file rule (A01/A02)
```powershell
curl.exe -s -o NUL -w "%{http_code}`n" -H "Host: shop.localhost" http://127.0.0.1:8000/.git/config
```
Blocking → `403`. Disabled → `200` (the demo shop deliberately exposes it) and the scan reports "Exposed sensitive files".

## 5. Error leakage (A10)
Sign in to the bank in a browser (`alice`/`alice123`), then open `http://bank.localhost:8000/report?id=abc`.
With **Generic error pages** ON you see "Something went wrong"; switch it OFF on the Policy tab and you see a Python stack trace.

## 6. Sensitivity and exclusions (A05)
Blocking mode, ShopEasy. Policy tab → set **Blocking threshold** to 100 → Save → re-run the attack guide: attacks now pass (threshold too high) and show as events with `detected`. Set it back to 5.
Exclusion: find the rule id in Events for a blocked `/search?q=` attack (e.g. 942100), add an exclusion (path `/search`, parameter `ARGS:q`, any reason) → that rule stops firing for `q`; other rules may still block.
If threshold changes have **no** effect, my phase-1 override assumption is wrong: tell me.

## 6b. Paranoia level
Raising paranoia only affects rules evaluated in phase 2 (most injection rules). Treat it as best-effort until you see a difference.

## 7. HTTPS (A04)
Policy tab → **Generate self-signed certificate** → HTTPS mode **Optional** → Save. Then:
```powershell
curl.exe -k -s -o NUL -w "%{http_code}`n" --resolve shop.localhost:8443:127.0.0.1 https://shop.localhost:8443/
```
Set **Redirect** and `curl.exe -s -o NUL -w "%{http_code} %{redirect_url}`n" -H "Host: shop.localhost" http://127.0.0.1:8000/` → `301` to `https://shop.localhost:8443/`.

## 8. Alerts (A09)
Site → **Alerts** → enable, email `ops@example.com`, Save, **Send test email**. Open `http://127.0.0.1:8025` (Mailpit) to read it. Attack the site repeatedly (≥5 critical events in 5 minutes) or switch Blocking → Disabled to trigger real alerts (within ~30 s).

## 9. Two-factor
Account → Set up two-factor sign-in → enter the key in an authenticator app → confirm → sign out and back in.

## 10. Coverage
**Coverage** page (admin) → **Run coverage tests** with both demo sites in Blocking mode. Statuses come only from what was actually observed.
