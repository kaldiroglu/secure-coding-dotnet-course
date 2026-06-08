# Chapter 15 (Cross-cutting) — CWE-20: Improper Input Validation & Sanitization

**Time budget:** ~40 min (Day-1 cross-cutting; slot after Ch 2 if time allows, else self-study) · **CWE:** CWE-20 · **Files:** `src/Vulnerable/Shop.Api/Controllers/CheckoutController.cs` ↔ `src/Fixed/Shop.Api/Controllers/CheckoutController.cs` (+ `src/Fixed/Shop.Api/Validation/CheckoutDto.cs`, `CheckoutValidator.cs`) · test `tests/Shop.Tests/InputValidationTests.cs`

> **Why this chapter exists.** Most other chapters fix a *specific* injection by validating or encoding at one spot. This chapter steps back and treats validation & sanitization as a **discipline**: where it belongs, the three tools for it, and the order they must run in. It ties together the validation threads in Ch 1 (parameterize, don't sanitize SQL), Ch 2 (bind to DTOs), Ch 3 (canonicalize then contain), Ch 10 (allow-list), and Ch 14 (strip control chars).

## The weakness in one line
A checkout endpoint trusts caller-supplied `quantity`, `unitPrice`, and a free-form `note` with no checks, so a negative quantity yields a negative total (free money) and hostile text flows straight through.

## Live demo script
1. Open the Vulnerable `CheckoutController`. Read the `// CWE-20` comment aloud — note there is *no* validation: `total = unitPrice * quantity` and the `note` is echoed raw.
2. Fire the exploit (cheat-sheet): POST `quantity = -5`, `unitPrice = 0.01` → `200 OK` with a **negative total**. The store now owes the attacker money.
3. POST a `note` containing a full-width `Ａ` and a `\r\n` → the response echoes it byte-for-byte.
4. Open the Fixed `CheckoutController` + `CheckoutDto` + `CheckoutValidator` side-by-side. Walk the three layers in order:
   - **DataAnnotations** (`CheckoutDto`): `[Range(1,100)]` on Quantity, `[Range(typeof(decimal),"0.01","100000")]` on UnitPrice. `[ApiController]` rejects bad *shape* with 400 before the action runs.
   - **FluentValidation** (`CheckoutValidator`): the *cross-field* rule `Quantity * UnitPrice <= 50,000` and the *business* rule "product must exist" — things DataAnnotations can't express.
   - **Normalize → sanitize** (`Sanitize`): `Normalize(FormKC)` folds the full-width `Ａ` to `A`, then control chars are stripped and whitespace collapsed.
5. Fire the same payloads at the Fixed app: negative quantity → `400`; over-cap order → `400`; the dirty note comes back as `"A hi there"`.
6. Run `dotnet test --filter FullyQualifiedName~InputValidationTests` → green.

## Why it's exploitable (the mechanism)
Model binding happily fills your DTO with whatever the client sends. Without constraints, "valid C#" (`int`, `decimal`, `string`) is not the same as "valid business input." A negative `int` is a perfectly good integer; a 10-million-unit order is a perfectly good multiplication. And a string that *looks* safe can be a different byte sequence than the one you checked — full-width, accented, or combining forms — so a validator that ran on the raw bytes is checking the wrong thing.

## The fix (and why it's layered)
Use the right tool per concern: **DataAnnotations for field shape** (range, length, required), **FluentValidation for relationships and business rules** (cross-field maths, existence, conditional rules), and **normalization + sanitization for free-form text**. Critically, **normalize first, then sanitize, then validate** — never validate before canonicalizing. Prefer allow-lists and fail closed.

> **Implementation note (a real bug we hit building this):** in a positional `record`, DataAnnotations must sit on the **constructor parameter** (`[Range(...)] int Quantity`), not on the generated property (`[property: Range(...)]`) — ASP.NET Core throws at request time otherwise. And `Range(typeof(decimal), "0.01", ...)` must set `ParseLimitsInInvariantCulture = true`, or the limit strings are parsed with the server's culture and blow up on comma-decimal locales. Both are exactly the kind of subtle validation-wiring mistakes this chapter is about.

## The transferable principle
> **Validate at the boundary: constrain shape, enforce business rules, and canonicalize before you check. "Parses as the right type" is not "is acceptable input."**

## "But what about…" — anticipated questions
- **Q:** Isn't this the same as Chapter 2 (mass assignment)? **A:** No. Ch 2 is about *which fields* the client may set (binding to a DTO). This is about *what values* those fields may hold once bound. You need both.
- **Q:** Why NFKC and not NFC? **A:** NFC only composes canonical equivalents. **NFKC** also applies *compatibility* folding — full-width `Ａ`→`A`, ligatures, etc. — which is what defeats the "looks different to the validator, same to everyone else" bypass. (Caveat: NFKC is lossy; use it for matching/sanitizing untrusted text, not for round-tripping data you must preserve exactly.)
- **Q:** DataAnnotations OR FluentValidation — why both? **A:** DataAnnotations are declarative and auto-run via `[ApiController]`, perfect for simple field shape. FluentValidation shines for cross-field/conditional/data-backed rules and is unit-testable in isolation. Using each where it's strongest keeps both readable.
- **Q:** Should I sanitize or reject? **A:** Reject structured input that's out of range (fail closed); sanitize only genuinely free-form text where cleaning is the expected behaviour (a display note). Never "sanitize" your way around a missing parameterization/encoding (see Ch 1, Ch 5).
