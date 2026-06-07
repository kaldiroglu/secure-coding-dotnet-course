# Chapter 12 — CWE-209: Sensitive Information in Error Messages

**Time budget:** ~40 min · **CWE:** CWE-209 · **Files:** `src/Vulnerable/Shop.Api/Controllers/DiagnosticsController.cs` ↔ `src/Fixed/Shop.Api/Controllers/DiagnosticsController.cs` · test `tests/Shop.Tests/ErrorExposureTests.cs`

## The weakness in one line

Unhandled exceptions are serialised with `ex.ToString()` and returned to the caller, leaking a full stack trace and a connection string containing `Password=P@ssw0rd-SECRET` in the response body.

## Live demo script

1. Open the Vulnerable `DiagnosticsController`. Read the `// CWE-209` comment aloud — point at `return StatusCode(500, ex.ToString())`. The exception message deliberately contains `"DB connection failed: Server=db;User=sa;Password=P@ssw0rd-SECRET"`.
2. Hit `GET /diagnostics/run` → the 500 response body contains the full `InvalidOperationException` message and call stack. Show the student where `P@ssw0rd-SECRET` appears verbatim in the JSON response.
3. Explain what an attacker learns from one request: the database server name, the SQL Server login name, the password, the .NET namespace structure, the file paths in the stack trace, and the framework version — a complete recon package for the next attack.
4. Open the Fixed `DiagnosticsController` side-by-side: `logger.LogError(ex, "Diagnostics run failed")` sends the full detail to the server-side log sink; `return StatusCode(500, new ProblemDetails { Title = "An unexpected error occurred.", Status = 500 })` sends only a generic message to the caller.
5. Hit the fixed endpoint → response body contains `"An unexpected error occurred."` — no password, no stack trace, no class names. The test `Fixed_error_is_generic` asserts `DoesNotContain("P@ssw0rd-SECRET")` and `DoesNotContain("InvalidOperationException")`.
6. Run `dotnet test --filter FullyQualifiedName~ErrorExposureTests` → green.

## Why it's exploitable (the mechanism)

Stack traces contain class names, method names, file paths, and line numbers that map directly to the application's internal structure. Exception messages frequently embed the data that caused the failure — connection strings, file paths, query text, and user input — because that is what makes them useful for debugging. Returning this to an unauthenticated caller is equivalent to handing an attacker a guided tour of the application's internals and credentials before they have even performed any active exploitation.

## The fix (and why it's usually less code)

Inject `ILogger<T>` and call `logger.LogError(ex, "...")` to record full detail server-side; return `new ProblemDetails { Title = "...", Status = 500 }` to the caller. In production, the ASP.NET Core exception-handler middleware (`app.UseExceptionHandler`) should be the centralised point for this pattern, catching any unhandled exception, logging it with a correlation ID, and returning a generic `ProblemDetails` — no per-controller try/catch required. The fix does not reduce information; it redirects it: operators and on-call engineers see everything in the log, attackers see nothing.

## The transferable principle

> **Errors reveal nothing useful to an attacker.**

## "But what about…" — anticipated questions

- **Q:** What about the Developer Exception Page in `app.UseDeveloperExceptionPage()`? **A:** The Developer Exception Page deliberately shows the full exception, stack trace, and request details — it is an intentional debug aid for the `Development` environment. Never enable it in `Staging` or `Production`. The standard pattern is `if (app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage(); else app.UseExceptionHandler("/error");`. The dangerous scenario is when this check is absent or the `ASPNETCORE_ENVIRONMENT` variable is left as `Development` in a production deployment.
- **Q:** How should the caller know which error to reference when they contact support? **A:** Return a correlation ID (a GUID generated per request, ideally from the `Trace-Id` header via `Activity.Current?.Id`) in the `ProblemDetails` instance field. Log the same ID server-side with the full exception. The caller can quote the ID to support, and the operator can look it up in the log aggregator without any sensitive detail ever leaving the server.
- **Q:** Isn't the `try/catch` in the controller the right place for this? **A:** For teaching it is the most visible location, but in production the `UseExceptionHandler` middleware is preferable. It catches exceptions from the entire pipeline (including model binding failures and middleware), applies the generic response unconditionally, and prevents any accidental missed catch block from leaking details. The per-controller try/catch is a last resort for cases that need specific handling; everything else should fall through to the middleware.
