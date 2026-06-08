# Secure Coding Checklist — .NET Backend

One line per principle. Pin it above your monitor.

1. **Never build queries from strings — parameterize.** (LINQ / `FromSqlInterpolated`, never `FromSqlRaw` with concatenation.)
2. **Bind to intent (DTOs), not to your entities.** Accept a DTO that exposes only what the client may set.
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
13. **Treat logs as untrusted readers — never log secrets.** No passwords, tokens, PII, or full request bodies.
14. **(Bonus) Neutralize newlines/control chars before logging untrusted data.** Strip CR/LF so input can't forge log entries (CWE-117).
15. **Validate at the boundary; canonicalize before you check.** Constrain shape (DataAnnotations), enforce cross-field/business rules (FluentValidation), and `Normalize(FormKC)` + strip control chars on free-form text *before* validating. "Parses as the type" ≠ "acceptable input" (CWE-20).

*For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev*
