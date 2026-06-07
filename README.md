# Secure Coding for .NET Backend Developers — Demo Solution

For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev

**Project:** Secure Coding for .NET Backend Developers (course demo codebase)
**Date:** 2026-06-07

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
- Each weakness is tagged in code with a `// CWE-XXX` comment.

## Architecture
- Two ASP.NET Core 8 Web API projects (`src/Vulnerable`, `src/Fixed`) with identical
  routes and distinct root namespaces (`dev.kaldiroglu.SecureCoding.Shop.Vulnerable`
  and `...Fixed`).
- EF Core 8 over SQLite; data seeded at startup.
- xUnit + `WebApplicationFactory` exploit tests prove each fix closes the hole.

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
