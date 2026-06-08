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
- Fix: LINQ/`FromSqlInterpolated` parameterizes — *less* code.
- Principle: **Never build queries from strings — parameterize.**

## Ch2 — CWE-915/20 Mass Assignment
- Bug: request body bound straight onto the EF `User` entity.
- Exploit: `POST /account/register` with `"isAdmin":true` → user becomes admin.
- Fix: bind a `RegisterDto` (Email/Password only); `IsAdmin` stays server-set.
- Principle: **Bind to intent (DTOs), not to your entities.**

## Ch3 — CWE-22 Path Traversal
- Bug: `Path.Combine(root, name)` doesn't collapse `..`.
- Exploit: `name=../secret.txt` → reads a file outside the folder.
- Fix: `Path.GetFullPath` + containment check (`StartsWith(root + separator)`).
- Principle: **Resolve the path, then verify it's inside the boundary.**

## Ch4 — CWE-78 OS Command Injection
- Bug: input concatenated into a shell line `/bin/sh -c "echo {title}"`.
- Exploit: `title=report; touch /tmp/pwned` → the injected command runs.
- Fix: `/bin/echo` + `ArgumentList.Add(title)` — no shell.
- Principle: **Pass arguments, never a command line.**

## Ch5 — CWE-79 Output Encoding
- Bug: stored review body written into HTML without encoding.
- Exploit: `body=<script>alert(1)</script>` reflected raw in the widget.
- Fix: `HtmlEncoder.Default.Encode` → `&lt;script&gt;` (inert).
- Principle: **Encode on output, per context.**

## Ch6 — CWE-639/862/863 Broken Access Control
- Bug: an order is returned by id with no ownership check (IDOR).
- Exploit: caller `X-User-Id: 2` reads `GET /orders/1` (another user's order).
- Fix: scope the query to the caller; return 404, not 403.
- Principle: **Authorize every object access, server-side.**

## Ch7 — CWE-327/916 Broken Crypto & Password Hashing
- Bug: unsalted MD5 passwords; AES in ECB mode.
- Exploit: same password → identical hash (== plain MD5); repeated plaintext blocks → repeated ciphertext blocks.
- Fix: `PasswordHasher` (PBKDF2 + per-hash salt); Data Protection API for encryption.
- Principle: **Never hand-roll crypto; use a real KDF for passwords.**

## Ch8 — CWE-330/338 Insecure Randomness
- Bug: token from `System.Random` seeded with a fixed/low-entropy value.
- Exploit: the token is reproduced from the seed (identical every call).
- Fix: `RandomNumberGenerator` (CSPRNG), 32 bytes.
- Principle: **Security tokens come from a CSPRNG.**

## Ch9 — CWE-798 Hardcoded Secrets
- Bug: API key as a compile-time `const` — shipped inside the binary.
- Exploit: authenticate with the source-visible key.
- Fix: read the key from `IConfiguration` (env / user-secrets / vault).
- Principle: **Secrets never belong in source.**

## Ch10 — CWE-918 SSRF
- Bug: the server fetches whatever URL the client supplies.
- Exploit: `url=http://127.0.0.1:<port>/` reaches an internal service.
- Fix: validate scheme, block loopback, allow-list hosts.
- Principle: **Allow-list outbound destinations; never let input pick where the server connects.**

## Ch11 — CWE-502/611 Deserialization & XXE
- Bug: Newtonsoft `TypeNameHandling.All`; XML with DTD + external resolver enabled.
- Exploit: `$type` gadget is instantiated (writes a file); XXE entity reads a local file.
- Fix: bind a typed DTO at default settings; `DtdProcessing.Prohibit`.
- Principle: **Never deserialize untrusted data into arbitrary types; disable DTDs.**

## Ch12 — CWE-209 Error Information Exposure
- Bug: returns `ex.ToString()` — stack trace + a connection string — to the caller.
- Exploit: `GET /diagnostics/run` → the secret leaks in the response body.
- Fix: log details server-side; return a generic `ProblemDetails`.
- Principle: **Errors reveal nothing useful to an attacker.**

## Ch13 — CWE-532 Sensitive Data in Logs
- Bug: the login endpoint logs the password.
- Exploit: `POST /session/login` → the password appears in the logs.
- Fix: log the username only; never the credential.
- Principle: **Treat logs as untrusted readers — never log secrets.**

## Ch14 (Bonus) — CWE-117 Log Forging
- Bug: untrusted input logged without neutralizing newlines.
- Exploit: `action` with an embedded `\n` forges a second, fake log entry.
- Fix: strip `\r`/`\n` before logging (content kept, on one line).
- Principle: **Neutralize newlines/control characters before writing untrusted data to a log.**
- Meta: surfaced by CodeQL after publishing — a weakness the core 13 missed.

## Ch15 (Cross-cutting) — CWE-20 Input Validation & Sanitization
- Bug: checkout trusts `quantity`/`unitPrice`/`note` — negative quantity = negative total.
- Fix: DataAnnotations (shape) + FluentValidation (cross-field/business) + normalize→sanitize (free text).
- Order: **normalize → sanitize → validate** (never validate before canonicalizing).
- Principle: **"Parses as the type" is not "acceptable input." Validate at the boundary.**
- Ties together Ch1/2/3/10/14.

## Coda — make habits automatic
- `dotnet list package --vulnerable` in CI.
- Roslyn security analyzers / Security Code Scan.
- GitHub CodeQL.
- The one-page checklist: 15 principles, one per chapter.
