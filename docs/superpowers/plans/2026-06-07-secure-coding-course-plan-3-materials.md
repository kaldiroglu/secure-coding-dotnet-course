# Secure Coding Course — Plan 3: Course Materials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce the instructor-facing course materials that wrap around the already-built demo solution: per-chapter speaker notes, an exploit cheat-sheet, slide outlines, a one-page secure-coding checklist, and an instructor run sheet.

**Architecture:** All materials are Markdown under a new `course/` directory. They are *grounded in the real code* already on `main` — each speaker note points at the actual `Vulnerable`/`Fixed` controller pair and its test, and the cheat-sheet's commands target the actual endpoints. No application code changes; this plan only adds documentation.

**Tech Stack:** Markdown only. The demo solution it documents is .NET 8 (13 vulnerable→fixed chapters, 32 passing tests on `main`).

**Companion docs:** spec `docs/superpowers/specs/2026-06-07-secure-coding-dotnet-course-design.md`; Plan 1 (Day-1 code) and Plan 2 (Day-2 code), both implemented & merged.

---

## File Structure (all new)
```
course/
├─ run-sheet.md                 # instructor run sheet: timetable + classroom setup + caveats
├─ checklist.md                 # one-page secure-coding checklist (the 13 principles)
├─ cheat-sheet.md               # ready-to-run exploit commands per chapter
├─ slides.md                    # minimal slide outline, one section per chapter
└─ chapters/
   ├─ 01-cwe-89-sql-injection.md
   ├─ 02-cwe-915-mass-assignment.md
   ├─ 03-cwe-22-path-traversal.md
   ├─ 04-cwe-78-command-injection.md
   ├─ 05-cwe-79-output-encoding.md
   ├─ 06-cwe-639-access-control.md
   ├─ 07-cwe-327-crypto-and-hashing.md
   ├─ 08-cwe-330-insecure-randomness.md
   ├─ 09-cwe-798-hardcoded-secrets.md
   ├─ 10-cwe-918-ssrf.md
   ├─ 11-cwe-502-deserialization-xxe.md
   ├─ 12-cwe-209-error-exposure.md
   └─ 13-cwe-532-sensitive-logging.md
```

## Master chapter table (authoritative inputs for the per-chapter tasks)

| # | File slug | CWE | Vulnerable ↔ Fixed controller | Test | Key endpoint(s) | Exploit payload | Transferable principle |
|---|-----------|-----|-------------------------------|------|-----------------|-----------------|------------------------|
| 1 | 01-cwe-89-sql-injection | CWE-89 | `ProductsController` | `SqliTests` | `GET /products/search?q=` | `zzz%' OR 1=1 --` | Never build queries from strings — parameterize. |
| 2 | 02-cwe-915-mass-assignment | CWE-915/20 | `AccountController` | `MassAssignmentTests` | `POST /account/register` | `{"email":"m@x.com","password":"pw","isAdmin":true}` | Bind to intent (DTOs), not to your entities. |
| 3 | 03-cwe-22-path-traversal | CWE-22 | `InvoicesController` | `PathTraversalTests` | `GET /invoices?name=` | `../secret.txt` | Resolve the path, then verify it's inside the boundary. |
| 4 | 04-cwe-78-command-injection | CWE-78 | `ReportsController` | `CommandInjectionTests` | `GET /reports/export?title=` | `report; touch /tmp/pwned` | Pass arguments, never a command line. |
| 5 | 05-cwe-79-output-encoding | CWE-79 | `ReviewsController` | `OutputEncodingTests` | `POST /reviews`, `GET /reviews/widget?productId=1` | `<script>alert(1)</script>` | Encode on output, per context. |
| 6 | 06-cwe-639-access-control | CWE-639/862/863 | `OrdersController` | `AccessControlTests` | `GET /orders/1` (+ header `X-User-Id: 2`) | request another user's order id | Authorize every object access, server-side. |
| 7 | 07-cwe-327-crypto-and-hashing | CWE-327/916 | `CryptoController` | `CryptoTests` | `POST /crypto/hash`, `POST /crypto/encrypt` | hash same password twice; encrypt repeated blocks | Never hand-roll crypto; use a real KDF for passwords. |
| 8 | 08-cwe-330-insecure-randomness | CWE-330/338 | `AccountRecoveryController` | `RandomnessTests` | `GET /account/reset-token` | reproduce token from the seed | Security tokens come from a CSPRNG. |
| 9 | 09-cwe-798-hardcoded-secrets | CWE-798 | `PartnerController` | `HardcodedSecretTests` | `POST /partner/webhook` (header `X-Api-Key`) | `sk_live_51HARDCODEDpartnerKEY` | Secrets never belong in source. |
| 10 | 10-cwe-918-ssrf | CWE-918 | `AvatarController` | `SsrfTests` | `POST /avatar/import` | `{"url":"http://127.0.0.1:<port>/"}` | Allow-list outbound destinations; never let input pick where the server connects. |
| 11 | 11-cwe-502-deserialization-xxe | CWE-502/611 | `ImportController` | `DeserializationTests` | `POST /import/json`, `POST /import/xml` | `$type` gadget JSON; DTD external-entity XML | Never deserialize untrusted data into arbitrary types; disable DTDs. |
| 12 | 12-cwe-209-error-exposure | CWE-209 | `DiagnosticsController` | `ErrorExposureTests` | `GET /diagnostics/run` | trigger the failure, read the body | Errors reveal nothing useful to an attacker. |
| 13 | 13-cwe-532-sensitive-logging | CWE-532 | `SessionController` | `LoggingTests` | `POST /session/login` | `{"username":"alice","password":"hunter2-SECRET"}` | Treat logs as untrusted readers — never log secrets. |

Controllers live at `src/{Vulnerable,Fixed}/Shop.Api/Controllers/<Name>.cs`; tests at `tests/Shop.Tests/<Name>.cs`.

---

## Task 1: Scaffold `course/` and write the speaker-note template + Chapter 1 (worked example)

**Files:**
- Create: `course/chapters/01-cwe-89-sql-injection.md`

This task establishes the canonical speaker-note shape that every other chapter copies. Chapter 1's content is given in full below.

- [ ] **Step 1: Create the directory and write Chapter 1.** Create `course/chapters/01-cwe-89-sql-injection.md` with EXACTLY:
```markdown
# Chapter 1 — CWE-89: SQL Injection

**Time budget:** ~55 min · **CWE:** CWE-89 · **Files:** `src/Vulnerable/Shop.Api/Controllers/ProductsController.cs` ↔ `src/Fixed/Shop.Api/Controllers/ProductsController.cs` · test `tests/Shop.Tests/SqliTests.cs`

## The weakness in one line
User input is concatenated into a raw SQL string, so the input can change the query's structure.

## Live demo script
1. Open the Vulnerable `ProductsController`. Read the `// CWE-89` line aloud — note `FromSqlRaw($"…{q}…")`.
2. Normal call (from the cheat-sheet): search `Laptop` → one row returned.
3. Fire the exploit: `q = zzz%' OR 1=1 --` → **all** products returned. The `%'` closes the `LIKE` pattern, `OR 1=1` is always true, `--` comments out the trailing fragment.
4. Open the Fixed `ProductsController` side-by-side: `db.Products.Where(p => p.Name.Contains(q))`. Note it is *less* code.
5. Fire the same payload at the Fixed app → empty result; the payload is treated as a literal value.
6. Run `dotnet test --filter FullyQualifiedName~SqliTests` → green.

## Why it's exploitable (the mechanism)
`FromSqlRaw` with an interpolated/concatenated string builds the SQL text before the database ever sees it, so attacker characters become part of the command, not data. EF Core cannot tell the difference between the developer's SQL and the attacker's.

## The fix (and why it's usually less code)
Let the provider parameterize: LINQ (`Where(...Contains...)`) or `FromSqlInterpolated($"… {q}")` sends the value as a bound parameter, so it can never alter the query structure. The fix removes string-building rather than adding validation.

## The transferable principle
> **Never build queries from strings — parameterize.**

## "But what about…" — anticipated questions
- **Q:** Isn't `FromSqlInterpolated($"...{q}")` the same as `FromSqlRaw($"...{q}")`? **A:** No — despite looking identical, `FromSqlInterpolated` turns the interpolation holes into parameters; `FromSqlRaw` does not. This near-identical pair is the classic trap.
- **Q:** We sanitize quotes — isn't that enough? **A:** No. Blocklisting characters is fragile (encodings, comment syntax, numeric contexts). Parameterization is the only complete fix.
- **Q:** Does an ORM make us immune? **A:** Only while you stay in LINQ. The moment you drop to raw SQL with concatenation, you're back to CWE-89.
```

- [ ] **Step 2: Commit.**
```bash
git add course/chapters/01-cwe-89-sql-injection.md
git commit -m "docs(course): speaker-note template + Chapter 1 (CWE-89)"
```

---

## Task 2: Speaker notes for Day-1 Chapters 2–6

**Files:**
- Create: `course/chapters/02-cwe-915-mass-assignment.md`
- Create: `course/chapters/03-cwe-22-path-traversal.md`
- Create: `course/chapters/04-cwe-78-command-injection.md`
- Create: `course/chapters/05-cwe-79-output-encoding.md`
- Create: `course/chapters/06-cwe-639-access-control.md`

- [ ] **Step 1: Write each file** using the EXACT same section structure as Chapter 1 (Task 1): the title line, **Time budget / CWE / Files** line, **The weakness in one line**, **Live demo script** (numbered, 5–6 steps ending in the `dotnet test --filter` run), **Why it's exploitable**, **The fix**, **The transferable principle** (blockquote), and **"But what about…"** (2–3 Q&A). For accuracy, READ the actual controller pair and test for each chapter before writing (paths in the master table). Use these per-chapter specifics:

  - **02 (CWE-915/20, `AccountController`, `MassAssignmentTests`):** weakness = model-binding the request body straight onto the EF `User` entity lets the client set `IsAdmin`. Demo: `POST /account/register` with `"isAdmin":true` → created user is admin (vuln); fixed binds a `RegisterDto` (Email/Password only) so `IsAdmin` stays server-set `false`. Principle: *Bind to intent (DTOs), not to your entities.* Q&A ideas: `[Bind]`/`[BindNever]` vs DTOs; why DTOs are clearer; note the plaintext-password field is intentional (hashing is Chapter 7).
  - **03 (CWE-22, `InvoicesController`, `PathTraversalTests`):** weakness = `Path.Combine(root, userName)` doesn't collapse `..`, so the OS resolves it out of the folder. Demo: `GET /invoices?name=../secret.txt` reads a sibling secret (vuln); fixed does `Path.GetFullPath` + containment check (`StartsWith(root + separator)`) → 400. Principle: *Resolve the path, then verify it's inside the boundary.* Q&A: why `Path.Combine` alone isn't enough; the trailing-separator bypass; allow-listing filenames.
  - **04 (CWE-78, `ReportsController`, `CommandInjectionTests`):** weakness = building a shell command line `/bin/sh -c "echo {title}"` with concatenated input. Demo: `title = report; touch <sentinel>` runs the injected command (vuln); fixed uses `/bin/echo` + `ArgumentList.Add(title)` (no shell) → inert. Principle: *Pass arguments, never a command line.* Note: POSIX-shell specific (macOS/Linux). Q&A: why arg arrays defeat metacharacters; escaping is not a fix; avoiding the shell entirely.
  - **05 (CWE-79, `ReviewsController`, `OutputEncodingTests`):** weakness = writing a stored review body into HTML without encoding (stored XSS). Demo: `POST /reviews` with body `<script>…`, then `GET /reviews/widget?productId=1` reflects raw script (vuln); fixed uses `HtmlEncoder.Default.Encode` → `&lt;script&gt;`. Principle: *Encode on output, per context.* Q&A: encode on output not input; context matters (HTML vs attribute vs JS vs URL); APIs returning JSON still need discipline when the data later lands in a page.
  - **06 (CWE-639/862/863, `OrdersController`, `AccessControlTests`):** weakness = returning an object by id with no ownership check (IDOR). Demo: caller `X-User-Id: 2` requests `GET /orders/1` (Alice's) → leaked (vuln); fixed scopes the query to the caller and returns 404 (not 403) to avoid leaking existence. Principle: *Authorize every object access, server-side.* IMPORTANT Q&A: the `X-User-Id` header is a **stand-in for a verified identity (e.g. a JWT subject)** — it is NOT a real auth pattern; never trust a raw client header for identity. Also: why 404 over 403; checking ownership in the query vs after fetch.

- [ ] **Step 2: Commit.**
```bash
git add course/chapters/02-*.md course/chapters/03-*.md course/chapters/04-*.md course/chapters/05-*.md course/chapters/06-*.md
git commit -m "docs(course): speaker notes for Day-1 chapters 2-6"
```

---

## Task 3: Speaker notes for Day-2 Chapters 7–13

**Files:**
- Create: `course/chapters/07-cwe-327-crypto-and-hashing.md`
- Create: `course/chapters/08-cwe-330-insecure-randomness.md`
- Create: `course/chapters/09-cwe-798-hardcoded-secrets.md`
- Create: `course/chapters/10-cwe-918-ssrf.md`
- Create: `course/chapters/11-cwe-502-deserialization-xxe.md`
- Create: `course/chapters/12-cwe-209-error-exposure.md`
- Create: `course/chapters/13-cwe-532-sensitive-logging.md`

- [ ] **Step 1: Write each file** using the SAME section structure as Chapter 1. READ the actual controller pair and test for each before writing. Per-chapter specifics:

  - **07 (CWE-327/916, `CryptoController`, `CryptoTests`):** two demos. (a) Hashing: vuln stores unsalted MD5 — same password → identical hash equal to plain MD5 (rainbow-tableable); fixed uses `PasswordHasher` (PBKDF2, per-hash salt) → hashes differ. (b) Encryption: vuln AES-**ECB** — identical plaintext blocks → identical ciphertext blocks; fixed uses the Data Protection API (non-deterministic). Principle: *Never hand-roll crypto; use a real KDF for passwords.* Q&A: why MD5/SHA-1 are wrong for passwords (fast + unsalted); why ECB leaks structure (show the "ECB penguin" idea verbally); why Data Protection over hand-rolled AES.
  - **08 (CWE-330/338, `AccountRecoveryController`, `RandomnessTests`):** weakness = `System.Random` seeded with a fixed/low-entropy value → token fully predictable (here identical every call); the test reproduces it from the seed. Fixed uses `RandomNumberGenerator`. Principle: *Security tokens come from a CSPRNG.* Q&A: `System.Random` vs `RandomNumberGenerator`; why `Guid.NewGuid()` is not a security token; even time-seeded `new Random()` is guessable.
  - **09 (CWE-798, `PartnerController`, `HardcodedSecretTests`):** weakness = API key as a compile-time `const` — it's in the binary, so it isn't secret; the test authenticates with the source-visible value. Fixed reads `IConfiguration` (env/user-secrets/vault). Principle: *Secrets never belong in source.* Q&A: the binary/decompilation point; `dotnet user-secrets` for dev; git-history leakage; rotation.
  - **10 (CWE-918, `AvatarController`, `SsrfTests`):** weakness = fetching a user-supplied URL lets the server reach internal services; the test stands up a real loopback listener the server reaches. Fixed validates scheme + blocks loopback + allow-lists hosts (`.example.com`). Principle: *Allow-list outbound destinations; never let input pick where the server connects.* Q&A: cloud metadata endpoints (169.254.169.254); why allow-list beats block-list; DNS-rebinding and private-IP ranges as the real-world hardening beyond this teaching allow-list.
  - **11 (CWE-502/611, `ImportController`, `DeserializationTests`):** two demos. (a) JSON: Newtonsoft `TypeNameHandling.All` lets `$type` pick the instantiated type — the demo gadget's setter writes a sentinel file (stand-in for RCE); fixed binds a typed DTO at default settings. (b) XXE: a DTD external entity reads a local file (vuln); fixed sets `DtdProcessing.Prohibit`. Principle: *Never deserialize untrusted data into arbitrary types; disable DTDs.* Q&A: why `TypeNameHandling` is dangerous; `BinaryFormatter` is obsolete/removed in .NET 8; DTD prohibition is the .NET 8 default (the vuln had to opt in).
  - **12 (CWE-209, `DiagnosticsController`, `ErrorExposureTests`):** weakness = returning `ex.ToString()` (stack trace + a connection string in the message) to the caller; fixed logs server-side and returns a generic `ProblemDetails`. Principle: *Errors reveal nothing useful to an attacker.* Q&A: never run the Developer Exception Page in production; `ProblemDetails`/exception-handler middleware as the real wiring; log details, return a correlation id.
  - **13 (CWE-532, `SessionController`, `LoggingTests`):** weakness = `LogInformation("… password={Password}", …)` writes the credential to logs; fixed logs only the username. Principle: *Treat logs as untrusted readers — never log secrets.* Q&A: logs flow to aggregators/3rd parties; passwords/tokens/PII/card data; redaction and structured logging; don't log full request bodies.

- [ ] **Step 2: Commit.**
```bash
git add course/chapters/07-*.md course/chapters/08-*.md course/chapters/09-*.md course/chapters/10-*.md course/chapters/11-*.md course/chapters/12-*.md course/chapters/13-*.md
git commit -m "docs(course): speaker notes for Day-2 chapters 7-13"
```

---

## Task 4: Exploit cheat-sheet

**Files:**
- Create: `course/cheat-sheet.md`

- [ ] **Step 1:** Create `course/cheat-sheet.md` with EXACTLY this content:
```markdown
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
curl -s "$V/reports/export?title=report%3B%20touch%20/tmp/scc-pwned"   # vuln: runs touch
ls /tmp/scc-pwned && rm /tmp/scc-pwned
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
```

- [ ] **Step 2: Commit.**
```bash
git add course/cheat-sheet.md
git commit -m "docs(course): exploit cheat-sheet"
```

---

## Task 5: One-page secure-coding checklist

**Files:**
- Create: `course/checklist.md`

- [ ] **Step 1:** Create `course/checklist.md` with EXACTLY this content:
```markdown
# Secure Coding Checklist — .NET Backend

One line per principle. Pin it above your monitor.

1. **Never build queries from strings — parameterize.** (LINQ / `FromSqlInterpolated`, never `FromSqlRaw` with concatenation.)
2. **Bind to intent, not to your entities.** Accept a DTO that exposes only what the client may set.
3. **Resolve the path, then verify it's inside the boundary.** `Path.GetFullPath` + containment check; allow-list names.
4. **Pass arguments, never a command line.** `ProcessStartInfo.ArgumentList`; no shell, no string interpolation.
5. **Encode on output, per context.** HTML-encode untrusted data where it lands; the context decides the encoder.
6. **Authorize every object access, server-side.** Scope queries to the caller; 404 over 403; never trust client-supplied ids/roles.
7. **Never hand-roll crypto; use a real KDF for passwords.** `PasswordHasher`/PBKDF2; Data Protection API for encryption.
8. **Security tokens come from a CSPRNG.** `RandomNumberGenerator`, never `System.Random` or `Guid`.
9. **Secrets never belong in source.** Configuration / user-secrets / vault; rotate; scan history.
10. **Allow-list outbound destinations.** Validate scheme/host; block loopback & private ranges; never let input pick the target.
11. **Never deserialize untrusted data into arbitrary types.** Bind typed DTOs; no `TypeNameHandling`; disable DTDs (`DtdProcessing.Prohibit`).
12. **Errors reveal nothing useful to an attacker.** Generic `ProblemDetails` to the caller; details to the log only.
13. **Treat logs as untrusted readers.** Never log passwords, tokens, PII, or full request bodies.

*For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev*
```

- [ ] **Step 2: Commit.**
```bash
git add course/checklist.md
git commit -m "docs(course): one-page secure-coding checklist"
```

---

## Task 6: Instructor run sheet

**Files:**
- Create: `course/run-sheet.md`

- [ ] **Step 1:** Create `course/run-sheet.md` with EXACTLY this content:
```markdown
# Instructor Run Sheet

*For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev*

## Before the room opens (setup)
1. Install the .NET 8 SDK (repo pins 8.0.x via `global.json`). Verify: `dotnet --version` → 8.0.x.
2. From the repo root: `dotnet build SecureCoding.NetBackend.sln` then `dotnet test` → expect **32 passing**.
3. Open the solution with the `Vulnerable` and `Fixed` projects side-by-side in the editor.
4. Two terminals, apps on pinned ports (no launch profile):
   - `ASPNETCORE_URLS=http://127.0.0.1:5101 dotnet run --project src/Vulnerable/Shop.Api --no-launch-profile`
   - `ASPNETCORE_URLS=http://127.0.0.1:5102 dotnet run --project src/Fixed/Shop.Api --no-launch-profile`
5. Keep `course/cheat-sheet.md` open in a third pane for copy-paste exploits.
6. For Ch10 (SSRF) have a throwaway internal server ready: `python3 -m http.server 9000`.

## Per-chapter rhythm (demo-heavy)
Read the `// CWE-XXX` line → fire the exploit on Vulnerable → show the Fixed diff (usually *less* code) → fire the same exploit on Fixed (blocked) → run that chapter's test filter green. Close on the one-line principle. Full speaker notes per chapter in `course/chapters/`.

## Day 1 — Injection · untrusted input · access control · output
| Time | Chapter |
|------|---------|
| 09:00 | Ch 0 — Orientation: secure coding vs appsec, the CWE spine, tour of the vuln app |
| 09:30 | Ch 1 — CWE-89 SQL injection |
| 10:25 | break |
| 10:40 | Ch 2 — CWE-915/20 mass assignment & validation |
| 11:30 | Ch 3 — CWE-22 path traversal |
| 12:20 | lunch |
| 13:20 | Ch 4 — CWE-78 OS command injection |
| 14:10 | Ch 5 — CWE-79 output encoding |
| 15:00 | break |
| 15:15 | Ch 6 — CWE-639/862/863 access-control checks (extended) |
| 16:20 | Day-1 recap + "spot the bug" Q&A |
| 17:00 | End |

## Day 2 — Crypto · secrets · SSRF · deserialization · error & log hygiene
| Time | Chapter |
|------|---------|
| 09:00 | Day-1 recap |
| 09:15 | Ch 7 — CWE-327/916 crypto & password hashing |
| 10:20 | break |
| 10:35 | Ch 8 — CWE-330/338 insecure randomness |
| 11:20 | Ch 9 — CWE-798 hardcoded secrets |
| 12:10 | lunch |
| 13:10 | Ch 10 — CWE-918 SSRF |
| 13:55 | Ch 11 — CWE-502/611 deserialization & XXE |
| 14:45 | break |
| 15:00 | Ch 12 — CWE-209 error info exposure |
| 15:40 | Ch 13 — CWE-532 sensitive data in logs |
| 16:15 | Coda — analyzers + the secure-coding checklist |
| 16:45 | Wrap-up / Q&A |
| 17:00 | End |

## Caveats to state out loud
- **SQLite, not SQL Server.** Chosen for zero setup; lessons are provider-agnostic. The CWE-89 demo shows the `OR 1=1` tautology (SQLite blocks stacked queries) — mention that SQL Server also enables stacked-query and `xp_cmdshell` payloads.
- **`X-User-Id` (Ch6) is a stand-in for a verified identity** (e.g. a JWT subject). It is NOT a real authentication pattern — never trust a raw client header for identity. The chapter teaches the *ownership check*, not auth design.
- **Ch4/Ch11 demos are POSIX/file-system specific** (macOS/Linux).

## Coda — make habits automatic
Briefly show: `dotnet list package --vulnerable`, Roslyn security analyzers / Security Code Scan, and GitHub CodeQL — so the room leaves knowing how to catch these in CI, not just in their heads.
```

- [ ] **Step 2: Commit.**
```bash
git add course/run-sheet.md
git commit -m "docs(course): instructor run sheet"
```

---

## Task 7: Slide outlines

**Files:**
- Create: `course/slides.md`

Minimal slides for a demo-heavy course: a few bullets per chapter, the code lives in the editor not on slides.

- [ ] **Step 1:** Create `course/slides.md`. Begin with the orientation section and Chapter 1 (given in full below), then add one section per remaining chapter (2–13) following the SAME 4-bullet shape, drawing the content from each chapter's speaker note (`course/chapters/NN-*.md`) and the master table principle.

Header + worked examples to start the file with:
```markdown
# Secure Coding for .NET Backend Developers — Slides

> Demo-heavy: each chapter is ~3 slides; the real content is the live vulnerable→fixed diff in the editor.

## Orientation
- Secure coding = not introducing weaknesses in the code you write (≠ appsec/threat-modeling).
- Spine: CWE — concrete code weaknesses, mapped to managed C# backend code.
- The app: one storefront Web API, in two twins — **Vulnerable** and **Fixed**.
- Format: watch the exploit, watch the fix, see the test go green.

## Ch1 — CWE-89 SQL Injection
- Bug: user input concatenated into raw SQL (`FromSqlRaw($"...{q}...")`).
- Exploit: `zzz%' OR 1=1 --` → returns every row.
- Fix: LINK/`FromSqlInterpolated` parameterizes — *less* code.
- Principle: **Never build queries from strings — parameterize.**
```
> Correct the obvious typo when authoring: the fix bullet should read "LINQ/`FromSqlInterpolated`".

Then sections `## Ch2 …` through `## Ch13 …`, each with exactly four bullets: **Bug**, **Exploit**, **Fix**, **Principle** (principle text from the master table).

- [ ] **Step 2: Commit.**
```bash
git add course/slides.md
git commit -m "docs(course): slide outlines"
```

---

## Task 8: Verification & proofread

- [ ] **Step 1: Structural check.** Confirm all expected files exist:
```bash
ls course/chapters/ | wc -l        # expect 13
ls course/run-sheet.md course/checklist.md course/cheat-sheet.md course/slides.md
```
Confirm `course/checklist.md` has 13 numbered principles and `course/cheat-sheet.md` + `course/slides.md` each cover all 13 chapters (grep for `Ch1`..`Ch13` / chapter headings).

- [ ] **Step 2: Accuracy check.** Spot-check three chapters' speaker notes against the real code: open the referenced controller pair and confirm the endpoint paths, payloads, and the "fix" API named in the note match what's actually in `src/`. Fix any drift.

- [ ] **Step 3: Confirm nothing else broke.** This plan is docs-only, but run `dotnet test` once → expect **32 passing** (unchanged).

- [ ] **Step 4: Final commit.**
```bash
git add -A
git commit -m "docs(course): verify materials complete and accurate" --allow-empty
```

---

## Self-Review notes
- **Spec coverage:** produces every deliverable the spec lists — per-chapter speaker notes (13), exploit cheat-sheet, slide outlines, one-page checklist, instructor run sheet.
- **Grounded in real code:** the master table maps each material to the actual controller pair / test / endpoint / payload built in Plans 1–2; per-chapter tasks instruct the author to READ the real files so notes can't drift from the implementation.
- **Complete content where bounded:** cheat-sheet, checklist, and run sheet are given verbatim (they're compact and concrete). The 13 speaker notes and slides use a complete template + a fully-worked Chapter-1 example + an exact per-chapter specifics list — DRY rather than 13× repetition, with no ambiguity about structure or content.
- **Carried-forward caveats are baked in:** the `X-User-Id`-is-not-real-auth caveat appears in both the Ch6 note (Task 2) and the run sheet (Task 6); the SQLite-vs-SQL-Server framing is in the run sheet; POSIX-specific demos are flagged.
- **No app code changes:** docs-only; Task 8 re-runs the suite purely to confirm the 32 tests are untouched.
```
