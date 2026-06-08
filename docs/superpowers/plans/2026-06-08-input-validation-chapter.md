# Input Validation & Sanitization Chapter (CWE-20) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new course chapter teaching input validation & sanitization (CWE-20) as a cross-cutting discipline — a Vulnerable/Fixed `CheckoutController` twin, a FluentValidation validator, a differential exploit test class, and updated course materials.

**Architecture:** Follow the existing twin-project pattern. A new `CheckoutController` in both `Vulnerable` and `Fixed`. The Fixed twin demonstrates three disciplines: DataAnnotations (field shape), FluentValidation (cross-field/business rules), and Unicode normalization + sanitization (free-form text), ordered normalize → sanitize → validate. The Vulnerable twin does none of these. Differential tests (in `tests/Shop.Tests`) prove the exploit works on Vulnerable and is blocked/cleaned on Fixed.

**Tech Stack:** ASP.NET Core 8 / C# 12, EF Core 8 + SQLite, FluentValidation 11.x, xUnit + WebApplicationFactory.

---

## File structure

- Create: `src/Vulnerable/Shop.Api/Controllers/CheckoutController.cs` — unvalidated checkout (tagged `// CWE-20`).
- Create: `src/Fixed/Shop.Api/Validation/CheckoutDto.cs` — DTO with DataAnnotations (shared by controller + validator).
- Create: `src/Fixed/Shop.Api/Validation/CheckoutValidator.cs` — FluentValidation cross-field/business rules.
- Create: `src/Fixed/Shop.Api/Controllers/CheckoutController.cs` — validated + sanitized checkout.
- Modify: `src/Fixed/Shop.Api/Shop.Api.csproj` — add FluentValidation package.
- Modify: `src/Fixed/Shop.Api/Program.cs` — register the validator.
- Create: `tests/Shop.Tests/InputValidationTests.cs` — 5 differential tests.
- Create: `course/chapters/15-cwe-20-input-validation.md` — speaker note.
- Modify: `course/cheat-sheet.md`, `course/checklist.md`, `course/slides.md`, `course/run-sheet.md` — chapter entries.
- Modify: `Test.md`, `README.md`, `course/proposal.md` — inventory/listing updates.

**Note (deviation from spec):** the spec sketched the DTO as nested in the controller; this plan promotes it to its own file `Validation/CheckoutDto.cs` so the controller and the FluentValidation validator can both reference it cleanly without a controller→validator→controller cycle. Functionally identical.

---

## Task 1: Vulnerable CheckoutController

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/CheckoutController.cs`
- Test: `tests/Shop.Tests/InputValidationTests.cs` (the two `Vulnerable_*` tests)

- [ ] **Step 1: Write the failing Vulnerable tests**

Create `tests/Shop.Tests/InputValidationTests.cs`:

```csharp
using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class InputValidationTests
{
    // Note is echoed in the response body so we can assert on validation/sanitization.
    public record OrderView(int Id, string Item, decimal Total, string? Note);

    private const string DirtyNote = "Ａ\r\n  hi  there  ";  // full-width A + CRLF + padding

    [Fact]
    public async Task Vulnerable_accepts_negative_quantity_producing_negative_total()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/checkout",
            new { productId = 1, quantity = -5, unitPrice = 0.01m, note = "x" });
        resp.EnsureSuccessStatusCode();
        var view = await resp.Content.ReadFromJsonAsync<OrderView>();
        Assert.True(view!.Total < 0);   // exploit: negative total accepted, no validation
    }

    [Fact]
    public async Task Vulnerable_stores_note_raw()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/checkout",
            new { productId = 1, quantity = 2, unitPrice = 10m, note = DirtyNote });
        resp.EnsureSuccessStatusCode();
        var view = await resp.Content.ReadFromJsonAsync<OrderView>();
        Assert.Equal(DirtyNote, view!.Note);   // raw: newline + full-width char survive untouched
    }
}
```

- [ ] **Step 2: Run the Vulnerable tests to verify they fail**

Run: `dotnet test tests/Shop.Tests --filter "FullyQualifiedName~InputValidationTests.Vulnerable"`
Expected: FAIL — the `/checkout` route does not exist yet, so the POST returns 404 and `EnsureSuccessStatusCode` throws.

- [ ] **Step 3: Implement the Vulnerable controller**

Create `src/Vulnerable/Shop.Api/Controllers/CheckoutController.cs`:

```csharp
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("checkout")]
public class CheckoutController(ShopDbContext db) : ControllerBase
{
    public record CheckoutDto(int ProductId, int Quantity, decimal UnitPrice, string? Note);

    // CWE-20: no validation of any kind. Negative/absurd quantity & price flow straight
    // into the total; the free-form note is echoed back raw (newlines, control chars and all).
    [HttpPost]
    public IActionResult Place([FromBody] CheckoutDto dto)
    {
        var item = db.Products.Find(dto.ProductId)?.Name ?? "unknown";
        var total = dto.UnitPrice * dto.Quantity;
        var order = new Order { OwnerId = 0, Item = item, Total = total };
        db.Orders.Add(order);
        db.SaveChanges();
        return Ok(new { order.Id, order.Item, order.Total, dto.Note });
    }
}
```

- [ ] **Step 4: Run the Vulnerable tests to verify they pass**

Run: `dotnet test tests/Shop.Tests --filter "FullyQualifiedName~InputValidationTests.Vulnerable"`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/Vulnerable/Shop.Api/Controllers/CheckoutController.cs tests/Shop.Tests/InputValidationTests.cs
git commit -m "feat(ch15): vulnerable CheckoutController + exploit tests (CWE-20)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: FluentValidation wiring (package + DTO + validator + registration)

**Files:**
- Modify: `src/Fixed/Shop.Api/Shop.Api.csproj`
- Create: `src/Fixed/Shop.Api/Validation/CheckoutDto.cs`
- Create: `src/Fixed/Shop.Api/Validation/CheckoutValidator.cs`
- Modify: `src/Fixed/Shop.Api/Program.cs`

- [ ] **Step 1: Add the FluentValidation package to the Fixed project**

In `src/Fixed/Shop.Api/Shop.Api.csproj`, add to the existing `<ItemGroup>` of `PackageReference`s:

```xml
    <PackageReference Include="FluentValidation" Version="11.11.0" />
```

The full `<ItemGroup>` becomes:

```xml
  <ItemGroup>
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="8.0.6" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="FluentValidation" Version="11.11.0" />
  </ItemGroup>
```

- [ ] **Step 2: Create the DataAnnotations DTO**

Create `src/Fixed/Shop.Api/Validation/CheckoutDto.cs`:

```csharp
using System.ComponentModel.DataAnnotations;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Validation;

// FIXED (CWE-20): DataAnnotations constrain field SHAPE. [ApiController] auto-returns
// 400 + ModelState BEFORE the action runs if any of these fail.
// Range(typeof(decimal), ...) is the precise form for money — avoids double rounding.
public record CheckoutDto(
    [property: Range(1, int.MaxValue)] int ProductId,
    [property: Range(1, 100)] int Quantity,
    [property: Range(typeof(decimal), "0.01", "100000")] decimal UnitPrice,
    [property: StringLength(200)] string? Note);
```

- [ ] **Step 3: Create the FluentValidation validator**

Create `src/Fixed/Shop.Api/Validation/CheckoutValidator.cs`:

```csharp
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using FluentValidation;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Validation;

// FIXED (CWE-20): FluentValidation expresses CROSS-FIELD and BUSINESS rules that
// DataAnnotations cannot — here a per-order total cap and a product-existence check.
public class CheckoutValidator : AbstractValidator<CheckoutDto>
{
    public const decimal PerOrderCap = 50_000m;

    public CheckoutValidator(ShopDbContext db)
    {
        RuleFor(x => x)
            .Must(dto => dto.UnitPrice * dto.Quantity <= PerOrderCap)
            .WithName("Total")
            .WithMessage($"Order total must not exceed {PerOrderCap}.");

        RuleFor(x => x.ProductId)
            .Must(id => db.Products.Any(p => p.Id == id))
            .WithMessage("Unknown product.");
    }
}
```

- [ ] **Step 4: Register the validator in Program.cs**

In `src/Fixed/Shop.Api/Program.cs`, add the two `using`s at the top (after the existing usings):

```csharp
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Validation;
using FluentValidation;
```

And register the validator immediately after `builder.Services.AddControllers();`:

```csharp
builder.Services.AddScoped<IValidator<CheckoutDto>, CheckoutValidator>();
```

- [ ] **Step 5: Build to verify wiring compiles**

Run: `dotnet build src/Fixed/Shop.Api`
Expected: Build succeeded (the controller using this DTO/validator comes in Task 3; this step only confirms the package restored and the validator/DTO compile).

- [ ] **Step 6: Commit**

```bash
git add src/Fixed/Shop.Api/Shop.Api.csproj src/Fixed/Shop.Api/Validation/CheckoutDto.cs src/Fixed/Shop.Api/Validation/CheckoutValidator.cs src/Fixed/Shop.Api/Program.cs
git commit -m "feat(ch15): add FluentValidation, CheckoutDto + CheckoutValidator (CWE-20)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Fixed CheckoutController (DataAnnotations + FluentValidation + sanitize)

**Files:**
- Create: `src/Fixed/Shop.Api/Controllers/CheckoutController.cs`
- Test: `tests/Shop.Tests/InputValidationTests.cs` (add the three `Fixed_*` tests)

- [ ] **Step 1: Add the failing Fixed tests**

Append these three `[Fact]` methods inside the `InputValidationTests` class in `tests/Shop.Tests/InputValidationTests.cs` (before the closing brace):

```csharp
    [Fact]
    public async Task Fixed_rejects_negative_quantity()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/checkout",
            new { productId = 1, quantity = -5, unitPrice = 0.01m, note = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);   // DataAnnotations [Range]
    }

    [Fact]
    public async Task Fixed_rejects_over_cap_order()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        // Every field is individually valid (qty<=100, price<=100000) but the product
        // 100 * 100000 = 10,000,000 blows the per-order cap -> only FluentValidation catches it.
        var resp = await client.PostAsJsonAsync("/checkout",
            new { productId = 1, quantity = 100, unitPrice = 100000m, note = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);   // FluentValidation cross-field
    }

    [Fact]
    public async Task Fixed_normalizes_and_sanitizes_note()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/checkout",
            new { productId = 1, quantity = 2, unitPrice = 10m, note = DirtyNote });
        resp.EnsureSuccessStatusCode();
        var view = await resp.Content.ReadFromJsonAsync<OrderView>();
        // NFKC folds full-width "A" -> "A"; control chars stripped; whitespace collapsed.
        Assert.Equal("A hi there", view!.Note);
    }
```

- [ ] **Step 2: Run the Fixed tests to verify they fail**

Run: `dotnet test tests/Shop.Tests --filter "FullyQualifiedName~InputValidationTests.Fixed"`
Expected: FAIL — `/checkout` does not exist in the Fixed app yet (404 → `BadRequest` assertions fail and `EnsureSuccessStatusCode` throws).

- [ ] **Step 3: Implement the Fixed controller**

Create `src/Fixed/Shop.Api/Controllers/CheckoutController.cs`:

```csharp
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Domain;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Validation;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.RegularExpressions;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("checkout")]
public class CheckoutController(ShopDbContext db, IValidator<CheckoutDto> validator) : ControllerBase
{
    [HttpPost]
    public IActionResult Place([FromBody] CheckoutDto dto)
    {
        // FIXED (CWE-20): [ApiController] has already enforced the DataAnnotations field
        // shape (it returns 400 + ModelState before we get here). Now apply the cross-field
        // / business rules that DataAnnotations cannot express.
        var result = validator.Validate(dto);
        if (!result.IsValid)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError(error.PropertyName, error.ErrorMessage);
            return ValidationProblem(ModelState);
        }

        // FIXED (CWE-20): free-form text is normalized then sanitized, in that order,
        // BEFORE it is trusted. Normalizing after validating would allow a canonicalization
        // bypass (a visually-equivalent string passes the check, then folds into the dangerous form).
        var note = Sanitize(dto.Note);

        var product = db.Products.Find(dto.ProductId)!;   // existence guaranteed by the validator
        var total = dto.UnitPrice * dto.Quantity;
        var order = new Order { OwnerId = 0, Item = product.Name, Total = total };
        db.Orders.Add(order);
        db.SaveChanges();
        return Ok(new { order.Id, order.Item, order.Total, Note = note });
    }

    // Normalize (NFKC) -> strip control chars -> collapse whitespace & trim.
    private static string Sanitize(string? input)
    {
        if (string.IsNullOrEmpty(input)) return "";
        var normalized = input.Normalize(NormalizationForm.FormKC);
        var noControl = new string(normalized.Where(c => !char.IsControl(c)).ToArray());
        return Regex.Replace(noControl, @"\s+", " ").Trim();
    }
}
```

- [ ] **Step 4: Run the Fixed tests to verify they pass**

Run: `dotnet test tests/Shop.Tests --filter "FullyQualifiedName~InputValidationTests.Fixed"`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the whole InputValidationTests class**

Run: `dotnet test tests/Shop.Tests --filter "FullyQualifiedName~InputValidationTests"`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add src/Fixed/Shop.Api/Controllers/CheckoutController.cs tests/Shop.Tests/InputValidationTests.cs
git commit -m "feat(ch15): fixed CheckoutController with validation + sanitization (CWE-20)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Speaker note (Chapter 15)

**Files:**
- Create: `course/chapters/15-cwe-20-input-validation.md`

- [ ] **Step 1: Write the speaker note**

Create `course/chapters/15-cwe-20-input-validation.md`:

```markdown
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

## The transferable principle
> **Validate at the boundary: constrain shape, enforce business rules, and canonicalize before you check. "Parses as the right type" is not "is acceptable input."**

## "But what about…" — anticipated questions
- **Q:** Isn't this the same as Chapter 2 (mass assignment)? **A:** No. Ch 2 is about *which fields* the client may set (binding to a DTO). This is about *what values* those fields may hold once bound. You need both.
- **Q:** Why NFKC and not NFC? **A:** NFC only composes canonical equivalents. **NFKC** also applies *compatibility* folding — full-width `Ａ`→`A`, ligatures, etc. — which is what defeats the "looks different to the validator, same to everyone else" bypass. (Caveat: NFKC is lossy; use it for matching/sanitizing untrusted text, not for round-tripping data you must preserve exactly.)
- **Q:** DataAnnotations OR FluentValidation — why both? **A:** DataAnnotations are declarative and auto-run via `[ApiController]`, perfect for simple field shape. FluentValidation shines for cross-field/conditional/data-backed rules and is unit-testable in isolation. Using each where it's strongest keeps both readable.
- **Q:** Should I sanitize or reject? **A:** Reject structured input that's out of range (fail closed); sanitize only genuinely free-form text where cleaning is the expected behaviour (a display note). Never "sanitize" your way around a missing parameterization/encoding (see Ch 1, Ch 5).
```

- [ ] **Step 2: Commit**

```bash
git add course/chapters/15-cwe-20-input-validation.md
git commit -m "docs(course): add Chapter 15 speaker note (CWE-20 input validation)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Update supporting course materials

**Files:**
- Modify: `course/cheat-sheet.md`, `course/checklist.md`, `course/slides.md`, `course/run-sheet.md`, `Test.md`, `README.md`, `course/proposal.md`

- [ ] **Step 1: cheat-sheet.md — add a cross-cutting block**

In `course/cheat-sheet.md`, immediately before the `## Bonus` line, insert:

```markdown
## Cross-cutting
**Ch15 — CWE-20 input validation & sanitization**
```bash
# Exploit: negative quantity -> negative total (the store owes the attacker)
curl -s -X POST "$V/checkout" -H 'Content-Type: application/json' \
  -d '{"productId":1,"quantity":-5,"unitPrice":0.01,"note":"x"}'        # vuln: total < 0
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$F/checkout" -H 'Content-Type: application/json' \
  -d '{"productId":1,"quantity":-5,"unitPrice":0.01,"note":"x"}'        # fixed: 400
# Sanitization: full-width A + CRLF in the note
curl -s -X POST "$F/checkout" -H 'Content-Type: application/json' \
  -d '{"productId":1,"quantity":2,"unitPrice":10,"note":"Ａ\r\n  hi  there  "}'  # fixed: note -> "A hi there"
```

```

- [ ] **Step 2: checklist.md — add a principle**

In `course/checklist.md`, after line 14 (the `(Bonus)` item) and before the `*For further enquiry...*` line, add:

```markdown
15. **Validate at the boundary; canonicalize before you check.** Constrain shape (DataAnnotations), enforce cross-field/business rules (FluentValidation), and `Normalize(FormKC)` + strip control chars on free-form text *before* validating. "Parses as the type" ≠ "acceptable input" (CWE-20).
```

- [ ] **Step 3: slides.md — add a slide**

In `course/slides.md`, insert this block immediately before the `## Coda — make habits automatic` line:

```markdown
## Ch15 (Cross-cutting) — CWE-20 Input Validation & Sanitization
- Bug: checkout trusts `quantity`/`unitPrice`/`note` — negative quantity = negative total.
- Fix: DataAnnotations (shape) + FluentValidation (cross-field/business) + normalize→sanitize (free text).
- Order: **normalize → sanitize → validate** (never validate before canonicalizing).
- Principle: **"Parses as the type" is not "acceptable input." Validate at the boundary.**
- Ties together Ch1/2/3/10/14.

```

- [ ] **Step 4: run-sheet.md — record the cross-cutting topic and refresh the test count**

In `course/run-sheet.md`, change the setup line:

```
2. From the repo root: `dotnet build SecureCoding.NetBackend.sln` then `dotnet test` → expect **32 passing**.
```
to:
```
2. From the repo root: `dotnet build SecureCoding.NetBackend.sln` then `dotnet test` → expect **39 passing**.
```

And in the Day 1 table, change the Ch 2 row:
```
| 10:40 | Ch 2 — CWE-915/20 mass assignment & validation |
```
to:
```
| 10:40 | Ch 2 — CWE-915/20 mass assignment & validation *(Ch 15 / CWE-20 input-validation is the natural deep-dive here if time allows; otherwise self-study)* |
```

- [ ] **Step 5: Test.md — add to the inventory and refresh the run note**

In `Test.md`, add a new section immediately before `## Run it with`:

```markdown
## Inventory (Cross-cutting)
| Test class | Weakness | Asserts |
|------------|----------|---------|
| `InputValidationTests` | CWE-20 | negative quantity → negative total (vuln) / 400 (fixed); over-cap order → 400 (fixed, FluentValidation); free-form note echoed raw (vuln) / NFKC-folded, control-stripped, whitespace-collapsed (fixed) |
```

- [ ] **Step 6: README.md — add to the weakness list**

In `README.md`, change the bonus line (line 29):
```
- Bonus chapter: CWE-117 (log forging) — surfaced by CodeQL after publishing.
```
to:
```
- Cross-cutting chapter: CWE-20 (input validation & sanitization) — DataAnnotations + FluentValidation + Unicode normalization.
- Bonus chapter: CWE-117 (log forging) — surfaced by CodeQL after publishing.
```

- [ ] **Step 7: proposal.md — promote input validation to a named module**

In `course/proposal.md`, in the "Cross-cutting throughout both days" section of the topic list, the input-validation idea is currently implicit. Add this as the first bullet of that section:

```markdown
- **Input validation & sanitization as a discipline (CWE-20)** — DataAnnotations for field shape, FluentValidation for cross-field/business rules, and Unicode normalization + sanitization for free-form text, in the correct order (normalize → sanitize → validate). Backed by a dedicated chapter with a vulnerable/fixed `CheckoutController` pair.
```

- [ ] **Step 8: Commit**

```bash
git add course/cheat-sheet.md course/checklist.md course/slides.md course/run-sheet.md Test.md README.md course/proposal.md
git commit -m "docs(course): wire Chapter 15 (CWE-20) into all course materials

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build the whole solution**

Run: `dotnet build SecureCoding.NetBackend.sln`
Expected: Build succeeded. The Fixed project should be clean (0 warnings from security analyzers on the new code). The Vulnerable project may emit analyzer warnings on `CheckoutController` — that is expected and intended.

- [ ] **Step 2: Run the full test suite**

Run: `dotnet test`
Expected: PASS — **39 tests** (34 prior + 5 new).

- [ ] **Step 3: Confirm no vulnerable packages were introduced**

Run: `./scripts/check-vulnerable-packages.sh`
Expected: `No vulnerable packages.` (FluentValidation 11.11.0 has no known advisories; if the script reports otherwise, bump to the latest patched 11.x and re-run.)

- [ ] **Step 4: Sanity-check analyzer output on the new files**

Run: `dotnet build src/Fixed/Shop.Api -warnaserror`
Expected: Build succeeded with no errors. If a security analyzer false-positives on the Fixed `CheckoutController` (e.g. on the regex or the DB lookup), suppress it **narrowly with a justifying comment** (follow the `#pragma` precedent in the Fixed `InvoicesController`) — never disable a rule solution-wide. Then re-run `dotnet build SecureCoding.NetBackend.sln`.

- [ ] **Step 5: Final commit (only if Step 4 required a suppression)**

```bash
git add src/Fixed/Shop.Api/Controllers/CheckoutController.cs
git commit -m "build(ch15): narrowly justify analyzer false-positive on Fixed CheckoutController

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Done criteria
- `dotnet test` → 39 passing.
- `./scripts/check-vulnerable-packages.sh` → no vulnerable packages.
- `dotnet build SecureCoding.NetBackend.sln` → succeeds; Fixed clean, Vulnerable may warn (intended).
- New chapter note + all six supporting materials updated; existing chapter numbering unchanged.
- All work committed on `main`.
```
