# Secure Coding for .NET Backend Developers — Introduction

*For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev*

## What this course is
A hands-on, demo-heavy **secure coding** course for .NET backend developers. Over two
days we work through the most common code-level weaknesses a backend developer can
introduce — and the idiomatic .NET 8 way to avoid each one. Every topic is shown as a
**before/after diff** in a real ASP.NET Core application: a deliberately vulnerable
endpoint, the exploit that breaks it, and the fix that closes it (usually *less* code).

## What this course is *not*
Secure coding is a focused slice of security — the code you actually type. To keep that
focus sharp, this course deliberately **excludes** the broader application-security
topics that deserve their own training:

| In scope (secure coding) | Out of scope (covered elsewhere) |
|---|---|
| Injection, encoding, deserialization | Threat modeling / STRIDE |
| Crypto-API misuse & password hashing | Security architecture & auth *system design* |
| Secrets in source, SSRF, error/log hygiene | Compliance (PCI, HIPAA, GDPR) |
| Code-level access-control checks (IDOR) | Pen testing, network/cloud/infra security |

## Who it's for
Mid-to-senior developers comfortable with C#, ASP.NET Core, EF Core, and dependency
injection, but without formal secure-coding training. We don't teach the framework — we
teach where it bites and how to use what it already gives you.

## Learning objectives
By the end you will be able to:
1. Recognize the **13 most common backend code weaknesses** by their CWE class.
2. Explain *why* each is exploitable in .NET terms — not in the abstract.
3. Apply the **idiomatic .NET 8 remediation** for each, from memory.
4. Carry away **13 transferable principles** (see `checklist.md`) that generalize beyond
   the specific bugs.

## How it's organized
- **The spine is CWE** (Common Weakness Enumeration) — concrete code weaknesses, filtered
  to what's reachable in managed C# backend code. (We use CWE rather than the OWASP Top 10,
  which is framed as application *risk categories* aimed at appsec/pentest work.)
- **One app, two twins.** A small storefront Web API exists in two forms — `Vulnerable`
  and `Fixed` — with identical routes. Each lesson is the diff between them, proven by a
  test that exploits the vulnerable side and confirms the fix blocks it.
- **Two days, 13 core chapters** (plus a CWE-117 log-forging bonus and a CWE-20
  input-validation cross-cutting chapter). Day 1: injection, untrusted input, access
  control, output. Day 2: crypto, secrets, SSRF, deserialization, error & log hygiene.
  Full timetable in `run-sheet.md`.

## How to use these materials
| File | Purpose |
|------|---------|
| `introduction.md` | This overview / Ch-0 orientation framing |
| `run-sheet.md` | Instructor timetable, classroom setup, caveats to state aloud |
| `chapters/NN-*.md` | Per-chapter speaker notes: demo script, mechanism, fix, principle, Q&A |
| `cheat-sheet.md` | Copy-paste `curl` exploits per chapter |
| `slides.md` | Minimal slide outline (the code is the real slide) |
| `checklist.md` | One-page takeaway: the 15 principles |

## Prerequisites
The .NET 8 SDK (the repo pins 8.0.x via `global.json`). Build with
`dotnet build SecureCoding.NetBackend.sln` and confirm the suite is green with
`dotnet test` (expect 39 passing). Setup details are in `run-sheet.md`.

## A few honest caveats
- The demo uses **SQLite** (zero classroom setup); the lessons are provider-agnostic.
- The access-control chapter's `X-User-Id` header is a **stand-in for a verified identity**
  (e.g. a JWT subject) — it teaches the ownership *check*, not authentication design, and
  is never a pattern to copy into real code.
- The command-injection and XXE demos are POSIX/file-system specific (macOS/Linux).

## The one habit to leave with
Most fixes here are *less* code than the bug, because the framework already does the safe
thing — you just have to use it. Secure coding is less about adding defenses and more about
**not reaching for the unsafe API in the first place.**
