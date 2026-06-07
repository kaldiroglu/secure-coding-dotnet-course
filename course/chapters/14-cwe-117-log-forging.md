# Chapter 14 (Bonus) — CWE-117: Log Forging

**Time budget:** ~30 min (bonus / optional) · **CWE:** CWE-117 · **Files:** `src/Vulnerable/Shop.Api/Controllers/AuditController.cs` ↔ `src/Fixed/Shop.Api/Controllers/AuditController.cs` · test `tests/Shop.Tests/LogForgingTests.cs`

> **Why this chapter exists.** It was surfaced by **CodeQL** (`cs/log-forging`) after we published the repo — a weakness the core 13 chapters didn't cover. That's the lesson in miniature: a scanner found something we missed. It's also distinct from Chapter 13 (CWE-532, *not logging secrets*) — here the data isn't secret, but it's **untrusted**, and writing it to a log unneutralized lets an attacker forge log entries.

## The weakness in one line
Untrusted input is written to the log without neutralizing newlines, so an attacker can inject CR/LF and forge additional, fake log entries.

## Live demo script
1. Open the Vulnerable `AuditController`. Note `logger.LogInformation("Audit: ... = {Action}", req.Action)` — structured logging does **not** strip newlines from the rendered value.
2. Fire the exploit (cheat-sheet): `action` = `view\n2026-06-08 00:00:00 [WARN] user 'admin' deleted all records`.
3. Show the app's console log: the forged line appears as its **own log entry**, indistinguishable from a real one — an auditor or log parser is now misled.
4. Open the Fixed `AuditController`: it strips `\r`/`\n` before logging. Fire the same payload → the forged text is collapsed onto one line, clearly part of the audited value.
5. Run `dotnet test --filter FullyQualifiedName~LogForgingTests` → green.

## Why it's exploitable (the mechanism)
The default logging formatter renders the parameter value verbatim into the message text. If that value contains `\n` (or `\r\n`), the log record spans multiple lines, and each injected line looks like a separate, legitimate entry. Attackers use this to hide their tracks, frame other users, or break/poison downstream log analysis and SIEM rules.

## The fix (and why it's usually less code)
Neutralize control characters in untrusted data before it reaches the log — here, strip `\r` and `\n` (`req.Action.Replace("\r", "").Replace("\n", "")`). The content is preserved on a single line; the structure of the log can no longer be controlled by input. (For richer needs, replace all control characters or log as structured JSON fields that a parser treats as data, not lines.)

## The transferable principle
> **Neutralize newlines/control characters in untrusted data before writing it to a log.**

## "But what about…" — anticipated questions
- **Q:** Doesn't structured logging (`{Action}`) already protect me? **A:** No. The placeholder keeps the value as a *property*, but the default text formatter still renders it with newlines intact into the message line. Structured *sinks* (JSON to a store) are safer; plain text/console sinks are forgeable.
- **Q:** Isn't this the same as Chapter 13? **A:** No. Ch13 (CWE-532) is about *not logging secrets*; this (CWE-117) is about *neutralizing untrusted content you legitimately log*. The audited action here isn't secret — but it's attacker-controlled.
- **Q:** Why not just trust the log viewer to escape it? **A:** You can't assume the consumer (grep, a SIEM, an auditor's eyes) neutralizes anything. Sanitize at the point you write.
