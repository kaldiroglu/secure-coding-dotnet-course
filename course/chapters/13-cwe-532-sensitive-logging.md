# Chapter 13 — CWE-532: Sensitive Information in Log Files

**Time budget:** ~35 min · **CWE:** CWE-532 · **Files:** `src/Vulnerable/Shop.Api/Controllers/SessionController.cs` ↔ `src/Fixed/Shop.Api/Controllers/SessionController.cs` · test `tests/Shop.Tests/LoggingTests.cs`

## The weakness in one line

The login endpoint logs the raw password as a named structured-log parameter, so every credential submitted to the application is permanently written to every log sink the application writes to.

## Live demo script

1. Open the Vulnerable `SessionController`. Read the `// CWE-532` comment aloud — point at the `LogInformation` call: `"Login attempt: user={User} password={Password}", req.Username, req.Password`. Note that `{Password}` is a named structured-logging hole; the credential is rendered as a log property value.
2. Show the test `LoggingTests.Vulnerable_login_logs_the_password`: it wires in a `ListLoggerProvider` (an in-memory sink), POSTs `{"username":"alice","password":"hunter2-SECRET"}`, and asserts `sink.Messages` contains `"hunter2-SECRET"`. A log aggregator, a file on disk, or a third-party logging service would receive exactly this.
3. Explain the blast radius: application logs flow to Splunk, Datadog, Elastic, Azure Monitor, or CloudWatch. Many organisations retain logs for 90 days or more. Anyone with read access to logs — including contractors, SIEM analysts, and the log vendor themselves — now has a rolling 90-day dump of user passwords.
4. Open the Fixed `SessionController` side-by-side: `logger.LogInformation("Login attempt for user {User}", req.Username)` — `{Password}` is simply gone. The username is useful for audit (who attempted to log in?) without exposing what they typed.
5. The test `Fixed_login_does_not_log_the_password` asserts `DoesNotContain(Password)` on the sink messages and `Contains("alice")` — confirming the username is still auditable.
6. Run `dotnet test --filter FullyQualifiedName~LoggingTests` → green.

## Why it's exploitable (the mechanism)

Structured logging (Serilog, Microsoft.Extensions.Logging, NLog) is designed to capture rich context — and it does so faithfully, including every named parameter passed to the log call. Unlike `Console.WriteLine`, structured logs are forwarded to aggregators, indexed, searched, and often exported. A password logged here is a password stored indefinitely in a system the developer did not build, maintained by people who are not on the security team, and possibly governed by a different data-retention policy. A single read path compromise (a stolen log query, a misconfigured S3 bucket, a rogue log-pipeline plugin) exposes every credential ever submitted.

## The fix (and why it's usually less code)

Remove `password={Password}, req.Password` from the log call. The fix is a deletion: `"Login attempt for user {User}"` with only `req.Username`. No masking, no redaction library, no configuration — just not passing the secret to the log method at all. The principle extends to tokens, card numbers, national ID numbers, and any other PII: if you do not log it, it cannot leak from the log.

## The transferable principle

> **Treat logs as untrusted readers — never log secrets.**

## "But what about…" — anticipated questions

- **Q:** What other values should never appear in logs? **A:** Passwords, tokens (bearer, refresh, API keys), session IDs, credit card numbers (PAN), CVV codes, social security / national ID numbers, full dates of birth, and any data your privacy policy classifies as sensitive. Also avoid logging full request bodies — they frequently contain form fields with credentials or PII even when the developer is not thinking about it.
- **Q:** What if we need to debug a login failure — can't we temporarily log the password? **A:** No. "Temporary" logging changes reach production and stay there. Instead, log the length or character-class distribution of what was provided (e.g., "password length=8, contains digit=true") if you genuinely need to diagnose input issues, or — better — reproduce the failure in a local environment with a test account. Never commit a log call that includes secrets, even behind a debug flag.
- **Q:** What about structured-logging redaction libraries? **A:** Libraries like Serilog's `Destructurama.Attributed` or custom enrichers can be configured to redact nominated properties before they reach sinks. These are useful as a safety net (e.g., to catch accidental logging of an object that contains a password property), but they are not a substitute for not logging the value in the first place. Redaction is a defence-in-depth measure; the primary control is: do not pass the secret to the logger at all.
