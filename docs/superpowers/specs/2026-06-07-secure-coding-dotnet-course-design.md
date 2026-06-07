# Secure Coding for .NET Backend Developers — Course Design

**Date:** 2026-06-07
**Author:** Akin Kaldiroglu (akin@kaldiroglu.dev)
**Status:** Approved design — ready for implementation planning

---

## 1. Purpose & framing

A **2-day, demo-heavy** training that teaches mid-to-senior .NET backend developers
**secure coding** — the developer-level discipline of writing code that does not
introduce vulnerabilities and that correctly uses the framework's safety mechanisms.

This is deliberately **not** a generic security course. The scope is the code a
developer types at the keyboard, organized around concrete code weaknesses.

### In scope (code-level weaknesses)
- Injection: SQL, OS command, path traversal
- Output encoding (XSS as a code-level encoding failure)
- Unsafe deserialization (incl. XXE)
- Crypto-API misuse and weak password hashing
- Insecure randomness
- Hardcoded secrets **in source code**
- Server-Side Request Forgery (unvalidated outbound URL in code)
- Information exposure via error messages
- Sensitive data in logs
- Improper input validation / mass assignment
- Access control **as code-level checks only** (missing/incorrect authorization,
  trusting client-supplied IDs or roles — IDOR)

### Explicitly out of scope (broader security, not secure coding)
- Threat modeling / STRIDE
- Security architecture and authentication/authorization **system design**
- Compliance (PCI, HIPAA, GDPR)
- Penetration testing / red teaming
- Network / cloud / infrastructure security
- Security operations, monitoring, incident response
- Secrets-management **infrastructure** (Key Vault setup, etc.)
- CSRF (CWE-352) — for a backend/API this is mostly framework configuration,
  which falls in the excluded appsec scope

## 2. Decisions (locked)

| Decision | Choice |
|----------|--------|
| Discipline | Secure coding only (code-level weaknesses) |
| Organizing spine | **CWE-based**, filtered to what is reachable in managed C# backend code |
| Access control | Included only as code-level checks (CWE-639/862/863) |
| Target runtime | **Modern .NET 8/9, C# 12** (BinaryFormatter obsolete, System.Text.Json default) |
| Audience | Mid-to-senior, security-naive (skip framework basics; go deep on weaknesses) |
| Delivery | 2 days, **demo-heavy** — instructor live-codes vulnerable→fixed; few/no formal labs |
| Structure | **Hybrid:** one runnable vulnerable Web API as the demo backbone, chaptered by CWE class, each chapter closing on a transferable principle |

### Why CWE over OWASP Top 10
CWE describes *code weaknesses* (CWE-89 SQL Injection, CWE-502 Deserialization)
that map one-to-one onto "things a developer typed wrong." OWASP Top 10 describes
*application risk categories* aimed at appsec/pentest framing, and some categories
drift into the excluded scope. CWE is the right vocabulary for a secure-coding course.

## 3. The demo backbone application

A single runnable **.NET 8 Web API** — a realistic **order/storefront backend** —
that the instructor lives in for the full two days. The domain is chosen so every
weakness class sits where a real backend would naturally have it.

### Repository structure
```
SecureCoding.NetBackend/
├─ README.md                      # project info + "Run it with" (per conventions)
├─ Test.md                        # test strategy / inventory (per conventions)
├─ src/
│  ├─ Vulnerable/                 # seeded vulnerable Web API (the demo spine)
│  │   └─ dev.kaldiroglu.SecureCoding.Shop.Api
│  └─ Fixed/                      # same endpoints, remediated — the "after"
│      └─ dev.kaldiroglu.SecureCoding.Shop.Api
└─ tests/
   └─ dev.kaldiroglu.SecureCoding.Shop.Tests   # tests proving each fix closes the hole
```

### Design choices
- **Twin projects, `Vulnerable/` + `Fixed/`**, with identical endpoints, so a live
  demo is a side-by-side diff and the gap between them is the lesson.
- **Each weakness is tagged in code** with a comment such as `// CWE-89: SQL Injection`
  so the code is navigable by weakness.
- **Tests run against the Fixed project** as executable proof a vulnerability is
  closed (e.g., fire `' OR '1'='1` and assert no rows returned). This doubles as the
  `Test.md` content.
- **SQLite or in-memory store** for zero classroom setup friction; runnable with one command.
- **`dev.kaldiroglu` root namespace** throughout, per global standards.

## 4. CWE chapter list

Each chapter = one weakness class, tied to a CWE ID, the specific .NET 8 footgun
(vulnerable → fixed), where it lives in the storefront app, and the transferable
principle it ends on. All filtered to what a managed-C# backend developer can
actually introduce.

### Day 1 — Injection · untrusted input · access control · output

| # | CWE | Footgun (vulnerable → fixed) | Lives in | Principle |
|---|-----|------------------------------|----------|-----------|
| 0 | — | *Orientation:* secure coding vs appsec, the CWE spine, tour of the vuln app | — | — |
| 1 | **CWE-89** SQL Injection | `FromSqlRaw($"…{q}")` / concat → `FromSqlInterpolated` / LINQ params | Product search | Never build queries from strings |
| 2 | **CWE-915 / 20** Mass assignment & weak validation | Model-binding to EF entity → DTO + `[ApiController]` validation | User registration | Bind to intent, not to your entity |
| 3 | **CWE-22** Path traversal | `Path.Combine(root, userName)` → canonicalize + `GetFullPath` containment + allow-list | Invoice download | Resolve, then verify it's inside the boundary |
| 4 | **CWE-78** OS command injection | `Process.Start` with shell + concatenated args → arg array, no shell, no interpolation | Report/export | Pass arguments, never a command line |
| 5 | **CWE-79** Output encoding | Returning/rendering stored review HTML unencoded → context-correct encoding, content-type discipline | Product reviews | Encode on output, per context |
| 6 | **CWE-639 / 862 / 863** Broken access-control checks | `Orders.Find(id)` with no ownership check; trusting client-sent role → server-side ownership/role checks, 404-not-403 | Order retrieval | Authorize every object access, server-side |

### Day 2 — Crypto · secrets · SSRF · deserialization · error & log hygiene

| # | CWE | Footgun (vulnerable → fixed) | Lives in | Principle |
|---|-----|------------------------------|----------|-----------|
| 7 | **CWE-327 / 916** Broken crypto & password hashing | MD5/SHA-1/custom AES (ECB) → `PasswordHasher`/Identity KDF; Data Protection API instead of hand-rolled | Login / stored cards | Never hand-roll crypto; use a real KDF |
| 8 | **CWE-330 / 338** Insecure randomness | `System.Random` / `Guid` for tokens → `RandomNumberGenerator` | Password-reset token | Security tokens need a CSPRNG |
| 9 | **CWE-798** Hardcoded secrets in code | API keys / connection strings in source → configuration & user-secrets (code-level only) | Config/startup | Secrets never belong in source |
| 10 | **CWE-918** SSRF | Outbound fetch of a user-supplied URL (product image / avatar) → allow-list outbound destinations | Image/avatar import | Never let input pick where the server connects |
| 11 | **CWE-502 (+ 611 XXE)** Unsafe deserialization | `BinaryFormatter` / Newtonsoft `TypeNameHandling.All`; unguarded `XmlReader` → safe types, DTD off | Import/restore | Never deserialize untrusted data into types |
| 12 | **CWE-209** Info exposure via errors | Leaking stack traces / SQL / connection strings → `ProblemDetails`, generic messages | Global error handling | Errors tell the user nothing useful to an attacker |
| 13 | **CWE-532** Sensitive data in logs | Logging passwords / tokens / PII → redaction, structured logging | Throughout | Treat logs as untrusted readers |
| — | — | *Coda:* turning habits automatic — Roslyn security analyzers / `dotnet list package --vulnerable` | — | — |

**13 weakness chapters** + orientation + coda ≈ 45–55 min each across two days,
which fits a demo-paced format with buffer.

## 5. Two-day timetable

Assumes ~9:00–17:00 with breaks; ~6 teaching hours/day. Demo-paced.

### Day 1 — Injection · untrusted input · access control · output
| Time | Chapter |
|------|---------|
| 09:00 | Ch 0 — Orientation |
| 09:30 | Ch 1 — CWE-89 SQL injection |
| 10:25 | *break* |
| 10:40 | Ch 2 — CWE-915/20 Mass assignment & validation |
| 11:30 | Ch 3 — CWE-22 Path traversal |
| 12:20 | *lunch* |
| 13:20 | Ch 4 — CWE-78 OS command injection |
| 14:10 | Ch 5 — CWE-79 Output encoding |
| 15:00 | *break* |
| 15:15 | Ch 6 — CWE-639/862/863 Access-control checks (extended) |
| 16:20 | Day-1 recap + "spot the bug" Q&A |
| 17:00 | End |

### Day 2 — Crypto · secrets · SSRF · deserialization · error & log hygiene
| Time | Chapter |
|------|---------|
| 09:00 | Day-1 recap |
| 09:15 | Ch 7 — CWE-327/916 Broken crypto & password hashing |
| 10:20 | *break* |
| 10:35 | Ch 8 — CWE-330/338 Insecure randomness |
| 11:20 | Ch 9 — CWE-798 Hardcoded secrets |
| 12:10 | *lunch* |
| 13:10 | Ch 10 — CWE-918 SSRF |
| 13:55 | Ch 11 — CWE-502 (+611 XXE) Unsafe deserialization |
| 14:45 | *break* |
| 15:00 | Ch 12 — CWE-209 Info exposure via errors |
| 15:40 | Ch 13 — CWE-532 Sensitive data in logs |
| 16:15 | Coda — analyzers + secure-coding checklist |
| 16:45 | Wrap-up / Q&A |
| 17:00 | End |

## 6. Deliverables

All within the one repository (Section 3):

1. **Twin-project solution** — `Vulnerable/` and `Fixed/` storefront Web APIs
   (identical endpoints), CWE-tagged in code, SQLite/in-memory, one-command run.
2. **Tests-as-proof** — per weakness, a test that fires the exploit and asserts the
   Fixed project resists it (feeds `Test.md`).
3. **Per-chapter speaker notes** (`/course/chapters/NN-cwe-xxx.md`) — one-line
   weakness, live exploit steps, the fix diff, the principle, anticipated
   "but what about…" questions, time budget.
4. **Exploit cheat-sheet** — ready-to-run `curl`/HTTP snippets per chapter so the
   instructor fires each attack live without fumbling.
5. **Slide outline** (markdown, minimal — demo-heavy) per chapter.
6. **One-page secure-coding checklist** handout — the 13 principles distilled.
7. **Instructor run sheet** — the timetable plus classroom setup steps.
8. **`README.md` + `Test.md`** at the root, per global conventions (project info,
   "Run it with" section, test inventory), `dev.kaldiroglu` root namespace throughout.

## 7. Open items for the implementation plan
- Exact storefront domain model (entities, endpoints) needed to host all 13 weaknesses
- Test framework choice (xUnit assumed) and how exploit tests are structured
- Whether the Fixed project is a separate project or a git branch/diff of Vulnerable
- Slide tooling/format (markdown only vs. a deck generator)

---

*For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev*
