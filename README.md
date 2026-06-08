# Secure Coding for .NET Backend Developers — Demo Solution

For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev

**Project:** Secure Coding for .NET Backend Developers (course demo codebase)
**Date:** 2026-06-07

## Start here
New to the course? Read **[course/introduction.md](course/introduction.md)** — the overview,
scope, learning objectives, and how to use the materials. Then see the
[instructor run sheet](course/run-sheet.md), [exploit cheat-sheet](course/cheat-sheet.md),
[one-page checklist](course/checklist.md), [slides](course/slides.md), and the per-chapter
speaker notes in [course/chapters/](course/chapters/). Practicing or contributing?
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Purpose & expected benefits
A teaching codebase for a 2-day, demo-heavy secure-coding course. It pairs a
deliberately **Vulnerable** ASP.NET Core 8 Web API with a **Fixed** twin so an
instructor can live-demo each weakness and its remediation as a side-by-side diff.

## Functional properties
- Storefront backend: product search, registration, invoices, reports, reviews, orders.
- Day-1 weaknesses: CWE-89 (SQL injection), CWE-915/20 (mass assignment),
  CWE-22 (path traversal), CWE-78 (command injection), CWE-79 (output encoding),
  CWE-639/862/863 (broken access-control checks).
- Day-2 weaknesses: CWE-327/916 (broken crypto & password hashing), CWE-330/338
  (insecure randomness), CWE-798 (hardcoded secrets), CWE-918 (SSRF), CWE-502/611
  (unsafe deserialization & XXE), CWE-209 (error info exposure), CWE-532 (sensitive data in logs).
- Cross-cutting chapter: CWE-20 (input validation & sanitization) — DataAnnotations + FluentValidation + Unicode normalization.
- Bonus chapter: CWE-117 (log forging) — surfaced by CodeQL after publishing.
- Each weakness is tagged in code with a `// CWE-XXX` comment.

## Architecture
- Two ASP.NET Core 8 Web API projects (`src/Vulnerable`, `src/Fixed`) with identical
  routes and distinct root namespaces (`dev.kaldiroglu.SecureCoding.Shop.Vulnerable`
  and `...Fixed`).
- EF Core 8 over SQLite; data seeded at startup.
- xUnit + `WebApplicationFactory` exploit tests prove each fix closes the hole.

## Security analyzers & CI
Static analysis is wired in solution-wide via `Directory.Build.props`:
- **Built-in .NET security rules** (`AnalysisModeSecurity=All`) plus **Security Code Scan**,
  run as **warnings, not errors** — so the `Vulnerable` project builds *and* lights up with
  findings (CA5351 MD5, CA5358 ECB, CA5394 insecure randomness, CA3006 command injection,
  CA2326/27 deserialization, CA3003/SCS0018 path traversal, SCS0002 SQL injection, …).
- This is a live demo: `dotnet build` surfaces ~20 security warnings, **all on `Vulnerable`**;
  the `Fixed` project is **clean**. The one place `Fixed` needs a `#pragma warning disable`
  (`InvoicesController`, path traversal) is a *justified, narrow* suppression — itself a
  teaching point: the code is validated, the taint analyzer just can't see the guard.

CI runs under `.github/workflows/` (active once the repo is pushed to GitHub):
- **`codeql.yml`** — GitHub CodeQL scan for C# on push/PR + weekly.
- **`dependency-security.yml`** — fails the build if `dotnet list package --vulnerable`
  reports anything. Run it locally with `./scripts/check-vulnerable-packages.sh`.

> Note: wiring the vulnerable-package check surfaced pre-existing High-severity advisories in
> transitive dependencies (System.Text.Json, Caching.Memory, and old test-tooling packages).
> They're remediated by patched top-level pins in `Directory.Build.props` — the same
> dependency hygiene the course's Day-2 coda teaches.

## Run it with
```bash
# Build everything
dotnet build SecureCoding.NetBackend.sln

# Run the vulnerable API
dotnet run --project src/Vulnerable/Shop.Api

# Run the fixed API
dotnet run --project src/Fixed/Shop.Api

# Run all exploit tests
dotnet test
```

## License
Licensed under the [MIT License](LICENSE) © 2026 Akin Kaldiroglu.
