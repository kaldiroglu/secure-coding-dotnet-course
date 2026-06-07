# Chapter 1 — CWE-89: SQL Injection

**Time budget:** ~55 min · **CWE:** CWE-89 · **Files:** `src/Vulnerable/Shop.Api/Controllers/ProductsController.cs` ↔ `src/Fixed/Shop.Api/Controllers/ProductsController.cs` · test `tests/Shop.Tests/SqliTests.cs`

## The weakness in one line
User input is concatenated into a raw SQL string, so the input can change the query's structure.

## Live demo script
1. Open the Vulnerable `ProductsController`. Read the `// CWE-89` line aloud — note `FromSqlRaw($"…{q}…")`.
2. Normal call (from the cheat-sheet): search `Laptop` → one row returned.
3. Fire the exploit: `q = zzz%' OR 1=1 --` → **all** products returned. The `%'` closes the `LIKE` pattern, `OR 1=1` is always true, `--` comments out the trailing fragment.
4. Open the Fixed `ProductsController` side-by-side: `db.Products.Where(p => p.Name.Contains(q))`. Note it is *less* code.
5. Fire the same payload at the Fixed app → empty result; the payload is treated as a literal value.
6. Run `dotnet test --filter FullyQualifiedName~SqliTests` → green.

## Why it's exploitable (the mechanism)
`FromSqlRaw` with an interpolated/concatenated string builds the SQL text before the database ever sees it, so attacker characters become part of the command, not data. EF Core cannot tell the difference between the developer's SQL and the attacker's.

## The fix (and why it's usually less code)
Let the provider parameterize: LINQ (`Where(...Contains...)`) or `FromSqlInterpolated($"… {q}")` sends the value as a bound parameter, so it can never alter the query structure. The fix removes string-building rather than adding validation.

## The transferable principle
> **Never build queries from strings — parameterize.**

## "But what about…" — anticipated questions
- **Q:** Isn't `FromSqlInterpolated($"...{q}")` the same as `FromSqlRaw($"...{q}")`? **A:** No — despite looking identical, `FromSqlInterpolated` turns the interpolation holes into parameters; `FromSqlRaw` does not. This near-identical pair is the classic trap.
- **Q:** We sanitize quotes — isn't that enough? **A:** No. Blocklisting characters is fragile (encodings, comment syntax, numeric contexts). Parameterization is the only complete fix.
- **Q:** Does an ORM make us immune? **A:** Only while you stay in LINQ. The moment you drop to raw SQL with concatenation, you're back to CWE-89.
