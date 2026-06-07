# Chapter 2 — CWE-915: Mass Assignment (Improper Control of Dynamically-Managed Code Resources / Insufficient Input Validation)

**Time budget:** ~50 min · **CWE:** CWE-915/20 · **Files:** `src/Vulnerable/Shop.Api/Controllers/AccountController.cs` ↔ `src/Fixed/Shop.Api/Controllers/AccountController.cs` · test `tests/Shop.Tests/MassAssignmentTests.cs`

## The weakness in one line
ASP.NET's model binder populates every public property on the bound type, so binding a request body directly onto an EF entity lets the client set fields (like `IsAdmin`) that were never meant to be user-controlled.

## Live demo script
1. Open the Vulnerable `AccountController`. Read the `// CWE-915` comment aloud — note `[FromBody] User user` binds the full EF entity.
2. Normal call: `POST /account/register` with `{"email":"alice@example.com","password":"pw"}` → 200, `isAdmin: false`.
3. Fire the exploit: `POST /account/register` with `{"email":"mallory@example.com","password":"pw","isAdmin":true}` → 200, **`isAdmin: true`**. The binder silently honoured the extra field.
4. Open the Fixed `AccountController` side-by-side: `[FromBody] RegisterDto dto` — the record exposes only `Email` and `Password`. Note the explicit `IsAdmin = false` on the entity construction.
5. Send the same exploit payload to the Fixed app → 200, but `isAdmin: false`; the DTO has no `IsAdmin` property so the binder has nowhere to write it.
6. Run `dotnet test --filter FullyQualifiedName~MassAssignmentTests` → green.

## Why it's exploitable (the mechanism)
ASP.NET's model binder uses reflection to match every JSON key in the body to a property of the target type by name. When the target type is the EF `User` entity, `isAdmin` in the JSON maps straight to `User.IsAdmin` — the binder does not know (and does not care) that the field is security-sensitive. The developer's intent was never expressed in the type, so the framework cannot enforce it.

## The fix (and why it's usually less code)
Introduce a dedicated `RegisterDto` record that exposes only the fields the client is allowed to supply (`Email`, `Password`). Bind to `RegisterDto` and then manually construct the entity, setting `IsAdmin = false` explicitly on the server. The framework's binder becomes a correct enforcer by design rather than an attack surface. No attribute magic, no `[BindNever]` scattered across a large entity — intent lives in the shape of the DTO.

## The transferable principle
> **Bind to intent (DTOs), not to your entities.**

## "But what about…" — anticipated questions
- **Q:** Can't we just put `[BindNever]` on `User.IsAdmin` instead of creating a DTO? **A:** You can, but it is fragile: every new sensitive property needs the attribute, and it is easy to forget. A DTO inverts the model — only explicitly listed fields are bindable, so adding a new property to the entity does not accidentally become a new attack surface. DTOs also make the API contract explicit.
- **Q:** Why does the Fixed code still have a plaintext `PasswordHash` field? **A:** Intentionally: this chapter is about mass assignment. Proper password hashing with `PasswordHasher<T>` (CWE-916) is the focus of the Day-2 crypto chapter. Mixing two fixes would obscure the lesson.
- **Q:** `[ApiController]` already validates `[Required]` — doesn't that protect us? **A:** `[ApiController]` enforces model-state validation (required fields, data-type constraints), but it only rejects *missing* fields. It cannot reject *extra* fields that map to dangerous properties, because the binder happily assigns them before validation runs.
