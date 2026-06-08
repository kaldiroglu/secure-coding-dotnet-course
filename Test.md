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

## Inventory (Day 2)
| Test class | Weakness | Asserts |
|------------|----------|---------|
| `CryptoTests` | CWE-327/916 | MD5 unsalted & == MD5 (vuln) / salted differ; ECB block-equality (vuln) / non-deterministic (fixed) |
| `RandomnessTests` | CWE-330/338 | token reproducible from seed & identical (vuln) / unique & 256-bit (fixed) |
| `HardcodedSecretTests` | CWE-798 | baked-in key accepted (vuln) / rejected, configured key accepted (fixed) |
| `SsrfTests` | CWE-918 | internal URL fetched (vuln) / loopback blocked 400 (fixed) |
| `DeserializationTests` | CWE-502/611 | `$type` gadget constructed + XXE file read (vuln) / ignored + DTD rejected (fixed) |
| `ErrorExposureTests` | CWE-209 | stack trace + connstring leaked (vuln) / generic ProblemDetails (fixed) |
| `LoggingTests` | CWE-532 | password in logs (vuln) / only username logged (fixed) |

## Inventory (Bonus)
| Test class | Weakness | Asserts |
|------------|----------|---------|
| `LogForgingTests` | CWE-117 | newline-forged log entry (vuln) / CR-LF neutralized (fixed) |

## Inventory (Cross-cutting)
| Test class | Weakness | Asserts |
|------------|----------|---------|
| `InputValidationTests` | CWE-20 | negative quantity → negative total (vuln) / 400 (fixed); over-cap order → 400 (fixed, FluentValidation); free-form note echoed raw (vuln) / NFKC-folded, control-stripped, whitespace-collapsed (fixed) |

## Run it with
```bash
dotnet test
# A single chapter, e.g.:
dotnet test --filter FullyQualifiedName~SqliTests
```
