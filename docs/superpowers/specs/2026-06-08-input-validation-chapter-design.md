# Design Spec — Chapter: Input Validation & Sanitization (CWE-20)

*Date: 2026-06-08 · Author: Akin Kaldiroglu (akin@kaldiroglu.dev)*

## Goal

Add a new chapter to the **Secure Coding for .NET Backend Developers** course that
teaches **input validation and sanitization as a cross-cutting discipline**, anchored
on **CWE-20 (Improper Input Validation)**. Today these ideas are taught only
incidentally inside other CWE fixes (Ch 1 SQLi, Ch 2 mass assignment, Ch 3 path
traversal, Ch 10 SSRF, Ch 14 log forging). This chapter pulls them together and adds
the pieces currently missing from the course: explicit `ModelState` handling, richer
DataAnnotations, FluentValidation for cross-field rules, and Unicode normalization.

It follows the established repo pattern: one **Vulnerable** controller, one **Fixed**
twin, one differential exploit test, one speaker note.

## Scope

**In scope**
- New `CheckoutController` (route `/checkout`) in both `Vulnerable` and `Fixed` projects.
- Three validation/sanitization disciplines demonstrated in the Fixed twin:
  1. **DataAnnotations** for field shape.
  2. **FluentValidation** for cross-field / business rules.
  3. **Unicode normalization + sanitization** for free-form text, ordered *before* validation.
- New differential test class (`InputValidationTests`).
- New speaker note `course/chapters/15-cwe-20-input-validation.md` + updates to the
  other course materials.

**Out of scope (YAGNI)**
- No FluentValidation auto-validation MVC pipeline (manual `IValidator` call, kept explicit).
- No new persisted DB column or EF migration (the `note` is echoed in the response, not stored as a column).
- No changes to the Vulnerable project's dependencies (it validates nothing — that is the lesson).
- No renumbering of existing chapters; no forcing a 7th slot into the full Day-1 timetable.

## Placement

Added as **`15-cwe-20-input-validation.md`**, a **cross-cutting / bonus chapter**
(handled like the Ch 14 bonus), **without renumbering** existing chapters. Rationale:
Day 1 and Day 2 timetables are already validated and full (09:00–17:00); inserting a
7th Day-1 slot would overflow them. In the materials it is marked a **Day-1
cross-cutting topic** — slot it after Ch 2 (mass assignment) if time allows, otherwise
self-study.

## Components

### Vulnerable `CheckoutController`
- File: `src/Vulnerable/Shop.Api/Controllers/CheckoutController.cs`
- `[Route("checkout")]`, `[ApiController]`, tagged `// CWE-20`.
- `POST /checkout` body `{ productId, quantity, unitPrice, note }`.
- No validation: `total = unitPrice * quantity`; persists an `Order` (reusing the
  existing `Order` domain type — `Item` = product name, `Total` = computed total);
  echoes `note` raw in the response. Negative/absurd values and control characters
  all flow through unchecked.

### Fixed `CheckoutController`
- File: `src/Fixed/Shop.Api/Controllers/CheckoutController.cs`
- Same route/shape. Constructor-injects `ShopDbContext` and `IValidator<CheckoutDto>`.
- DTO `CheckoutDto` with DataAnnotations (field shape):
  - `[Required] int ProductId`
  - `[Range(1, 100)] int Quantity`
  - `[Range(0.01, 100000)] decimal UnitPrice`
  - `[StringLength(200)] string? Note`
- `[ApiController]` auto-runs DataAnnotations and returns `400 + ModelState` before the
  action body (made explicit with a comment; an explicit `if (!ModelState.IsValid)`
  guard is shown for teaching clarity).
- Then an explicit `_validator.Validate(dto)` call (FluentValidation). On failure,
  copy errors into `ModelState` and return `ValidationProblem(ModelState)`.
- Then normalize + sanitize `note` (see below), compute total, save, return `200`.

### `CheckoutValidator` (FluentValidation)
- File: `src/Fixed/Shop.Api/Validation/CheckoutValidator.cs`
- Cross-field / business rules DataAnnotations cannot express cleanly:
  - `Quantity * UnitPrice` must be ≤ a per-order cap (e.g. `50000`).
  - `ProductId` must reference a product that exists (looked up via `ShopDbContext`).

### Normalization + sanitization (Fixed `note`)
Ordered **normalize → sanitize → (validation already ran for shape)**. The ordering is
itself the lesson — normalizing *after* validating enables canonicalization bypass.
1. `note.Normalize(NormalizationForm.FormKC)` (NFKC) — folds compatibility variants
   (e.g. full-width `ＡＤＭＩＮ` → `ADMIN`, ligatures) so visually-equivalent-but-byte-different
   strings can't slip past checks.
2. Strip control characters (`Char.IsControl`, which covers the CR/LF of Ch 14).
3. Trim and collapse internal whitespace.

### Wiring (Fixed project only)
- Add `FluentValidation` (v11.x) to `src/Fixed/Shop.Api/Shop.Api.csproj`.
- Register in Fixed `Program.cs`:
  `builder.Services.AddScoped<IValidator<CheckoutDto>, CheckoutValidator>();`
- Confirm `./scripts/check-vulnerable-packages.sh` stays clean after the add.

## Data flow

```
Client → POST /checkout {productId, quantity, unitPrice, note}
  Vulnerable: bind → total = unitPrice*quantity → save Order(Total, note raw) → 200 {id, total, note}
  Fixed:     bind → DataAnnotations (ModelState) → 400 if field shape bad
                  → CheckoutValidator.Validate → ValidationProblem if business rule bad
                  → normalize+sanitize(note) → total = unitPrice*quantity → save → 200 {id, total, note}
```

## Testing

New `tests/Shop.Tests/InputValidationTests.cs`, using existing
`VulnerableFactory`/`FixedFactory` (isolated in-memory SQLite). Differential — each
test would fail if the Fixed controller skipped the step it targets.

1. `Vulnerable_accepts_negative_quantity_producing_negative_total` — `quantity=-5, unitPrice=0.01`
   → `200`, returned `total < 0`. *(exploit succeeds)*
2. `Fixed_rejects_negative_quantity` — same payload → `400 BadRequest`, no order created.
   *(DataAnnotations `[Range]`)*
3. `Fixed_rejects_over_cap_order` — field-valid but `quantity*unitPrice` over the cap →
   `400`. *(FluentValidation cross-field rule fires independently of DataAnnotations)*
4. `Fixed_normalizes_and_sanitizes_note` vs `Vulnerable_stores_note_raw` — `note` =
   `"Ａ\r\n  hi  there  "` → Fixed returns NFKC-folded, control-char-free,
   whitespace-collapsed text; Vulnerable returns it raw. *(differential)*

Full suite goes **34 → 39** tests.

## Materials to update (docs-only, no renumber)

- **New** `course/chapters/15-cwe-20-input-validation.md` — same 8-section speaker-note structure.
- `course/cheat-sheet.md`, `course/checklist.md`, `course/slides.md` — add the CWE-20 entry/exploit/principle.
- `course/run-sheet.md` — list as a **Day-1 cross-cutting** topic.
- `Test.md` — add the new test class.
- `README.md` — add to the chapter list.
- `course/proposal.md` — promote "input validation & sanitization" to a named module.

## Key teaching points

- **DataAnnotations for field shape; FluentValidation for relationships/business rules;
  normalization + sanitization for free-form text.**
- **Normalize → sanitize → validate, in that order** — validating before normalizing is
  the classic canonicalization bypass.
- NFKC over NFC: compatibility folding catches more attack variants (full-width,
  ligatures). Ties to the canonicalization stories in Ch 3 (path traversal) and Ch 10 (SSRF).
- Allowlist / fail-closed mindset, consistent with the rest of the course.

## Acceptance criteria

- Both `CheckoutController`s exist and build; Vulnerable tagged `// CWE-20`.
- `dotnet test` → 39 passing.
- `./scripts/check-vulnerable-packages.sh` → no vulnerable packages.
- Security analyzers: Fixed stays clean (or any analyzer false-positive narrowly
  suppressed with justification); Vulnerable may light up (intended).
- All listed materials updated; existing chapter numbering unchanged.
