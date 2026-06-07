# Tests

For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev

## Type of tests
**Integration / exploit tests.** Each test boots the real Web API in memory via
`WebApplicationFactory` and fires the actual attack over HTTP. For every weakness:
- the **Vulnerable** app is asserted to be exploitable (proving the demo is real), and
- the **Fixed** app is asserted to block the same attack (proving the remediation works).

Each app runs on its own isolated in-memory SQLite connection per test (see
`tests/Shop.Tests/Factories.cs`), so tests do not share state.

## Inventory (Day 1)
| Test class | Weakness | Asserts |
|------------|----------|---------|
| `SqliTests` | CWE-89 | tautology leaks all rows (vuln) / matches nothing (fixed) |
| `MassAssignmentTests` | CWE-915/20 | `isAdmin:true` honored (vuln) / ignored (fixed) |
| `PathTraversalTests` | CWE-22 | `../secret.txt` read (vuln) / 400 (fixed) |
| `CommandInjectionTests` | CWE-78 | `; touch` runs (vuln) / inert (fixed) — POSIX shell |
| `OutputEncodingTests` | CWE-79 | raw `<script>` reflected (vuln) / encoded (fixed) |
| `AccessControlTests` | CWE-639/862/863 | cross-user read (vuln) / 404 (fixed) |

## Run it with
```bash
dotnet test
# A single chapter, e.g.:
dotnet test --filter FullyQualifiedName~SqliTests
```
