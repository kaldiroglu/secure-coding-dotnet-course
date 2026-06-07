# Chapter 4 — CWE-78: OS Command Injection

**Time budget:** ~50 min · **CWE:** CWE-78 · **Files:** `src/Vulnerable/Shop.Api/Controllers/ReportsController.cs` ↔ `src/Fixed/Shop.Api/Controllers/ReportsController.cs` · test `tests/Shop.Tests/CommandInjectionTests.cs`

## The weakness in one line
Building a shell command string by concatenating user input hands the attacker the shell's full metacharacter vocabulary (`;`, `|`, `$()`, backticks) and lets them append arbitrary commands.

## Live demo script
1. Open the Vulnerable `ReportsController`. Read the `// CWE-78` comment aloud — note `new ProcessStartInfo("/bin/sh", $"-c \"echo {title}\"")`: the title is interpolated directly into the shell command string.
2. Normal call: `GET /reports/export?title=report` → output `report`. The shell ran `echo report` and returned the text.
3. Fire the exploit: `GET /reports/export?title=report; touch /tmp/scc-pwned-vuln.txt`. The shell sees `echo report; touch …` — two commands separated by `;`. Verify the sentinel file was created.
4. Open the Fixed `ReportsController` side-by-side: `new ProcessStartInfo("/bin/echo")` — no shell — and `psi.ArgumentList.Add(title)` passes the title as a discrete argument. Note the `ArgumentList` API (not `Arguments` string).
5. Send the same payload to the Fixed app → output `report; touch /tmp/scc-pwned-fixed.txt` (the semicolon is echoed as a literal character, not executed). Confirm the fixed sentinel file was **not** created.
6. Run `dotnet test --filter FullyQualifiedName~CommandInjectionTests` → green.

## Why it's exploitable (the mechanism)
When `ProcessStartInfo` launches `/bin/sh -c "…"`, the entire second argument is handed to the POSIX shell as a complete command line. The shell parses metacharacters before executing anything, so a `;` in the user-supplied `title` terminates the `echo` command and begins a new one. No amount of quoting in the surrounding template can reliably neutralise all shell metacharacters across every shell and every context.

## The fix (and why it's usually less code)
Invoke the target binary directly (`/bin/echo`) and supply arguments through `ProcessStartInfo.ArgumentList` rather than a command string. `ArgumentList` is passed to the OS `execve`-style interface — each element becomes a discrete argument with no shell parsing step at all. Shell metacharacters in the value are received by the program as literal characters. The fix removes the shell from the call entirely rather than trying to sanitise for it.

## The transferable principle
> **Pass arguments, never a command line.**

## "But what about…" — anticipated questions
- **Q:** Can't we just escape the metacharacters in the title before interpolating? **A:** No. The set of shell metacharacters varies by shell, encoding context, and shell version. Escaping is fragile and error-prone; engineers regularly miss corner cases (newlines, `$IFS`, process substitution). Removing the shell from the equation is the only complete fix.
- **Q:** Why use `ArgumentList` instead of the `Arguments` string property on `ProcessStartInfo`? **A:** `Arguments` is still a string that .NET formats and hands to the OS command-line parser; on Windows that involves quoting rules that can be exploited. `ArgumentList` maps each entry to a distinct `argv[]` slot with no shell or command-line parser involved — it is the correct API for passing untrusted data as arguments.
- **Q:** This demo is POSIX-specific — what about Windows? **A:** On Windows the attack vector is `cmd.exe /C "…"` with `&`, `|`, `^` as metacharacters. The fix is identical: use `ArgumentList` and invoke the target executable directly. The underlying principle — avoid the shell — is platform-independent.
