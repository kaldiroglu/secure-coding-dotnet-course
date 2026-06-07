# Contributing & Practicing

*For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev*

This is the teaching codebase for the **Secure Coding for .NET Backend Developers** course.
It's written for **attendees** — to practice in during and after the workshop — and for
instructors extending it. New here? Start with [course/introduction.md](course/introduction.md).

## The golden rule
There are two twin projects: `src/Vulnerable/Shop.Api` is **deliberately insecure**, and
`src/Fixed/Shop.Api` is its remediated twin. **Do not "fix" the Vulnerable project** — its
flaws are the teaching material. Security-analyzer warnings and CodeQL alerts on `Vulnerable/`
are *expected and intended*. Put any remediation in `Fixed/`.

## Setup
- .NET 8 SDK (pinned via `global.json`; check with `dotnet --version` → `8.0.x`).
- `dotnet build SecureCoding.NetBackend.sln`
- `dotnet test` → all green (currently 34 tests).
- To play with the live exploits, run both apps on pinned ports and use
  [course/cheat-sheet.md](course/cheat-sheet.md):
  ```bash
  ASPNETCORE_URLS=http://127.0.0.1:5101 dotnet run --project src/Vulnerable/Shop.Api --no-launch-profile
  ASPNETCORE_URLS=http://127.0.0.1:5102 dotnet run --project src/Fixed/Shop.Api --no-launch-profile
  ```

## How to practice (the core exercise)
For any chapter (notes in `course/chapters/`):
1. Read the **Vulnerable** controller and its `// CWE-XXX` tag; fire the exploit from the
   cheat-sheet and watch it work.
2. **Before peeking at the Fixed version**, try writing the remediation yourself in `Fixed/`.
3. Prove it with a **differential test** in `tests/Shop.Tests/`: the exploit must *succeed*
   against Vulnerable and be *blocked* against Fixed.
4. `dotnet test --filter FullyQualifiedName~<YourTest>` until green, then compare with the
   shipped `Fixed/` controller.

A good test is **differential** — it would fail if the controller did nothing. Use the
existing tests (e.g. `SqliTests`, `SsrfTests`) as templates; the `VulnerableFactory` /
`FixedFactory` helpers boot each app on its own isolated in-memory SQLite database.

## Conventions (match the existing code)
- **Namespaces:** `dev.kaldiroglu.SecureCoding.Shop.Vulnerable.*` and `...Shop.Fixed.*`
  (distinct roots so one test project can reference both without type collisions).
- **Tag** each weakness in code with `// CWE-XXX: short description`.
- **One chapter = one controller pair + one exploit test** (plus a speaker note if you add a chapter).
- **Analyzers are warnings, not errors** (`Directory.Build.props`). If an analyzer
  false-positives on correct `Fixed/` code, suppress it *narrowly with a justification*
  (see the path-traversal `#pragma` in the Fixed `InvoicesController`) — never disable a
  rule solution-wide.
- **Keep dependencies patched:** `./scripts/check-vulnerable-packages.sh` must report none.
- **Never commit real secrets.** The hardcoded keys in `Vulnerable/` are fake demo values.

## Adding a new chapter (advanced / instructors)
Follow the pattern documented in `docs/superpowers/plans/`:
1. Vulnerable controller (tagged) + Fixed controller (idiomatic remediation) + differential exploit test.
2. Speaker note `course/chapters/NN-cwe-xxx.md` — copy the 8-section structure from any existing note.
3. Update `course/cheat-sheet.md`, `course/checklist.md`, `course/slides.md`, and `Test.md`.

## Proposing changes
- Branch (or fork) off `main` and open a Pull Request.
- CI must pass: **tests**, **CodeQL**, and **dependency-security**.
  - CodeQL *will* report alerts on the `Vulnerable/` project — that's expected; a PR shouldn't
    try to silence them. New alerts on `Fixed/` should be fixed or justified.
- Keep commits focused; the existing history uses conventional prefixes
  (`feat(chN):`, `docs(course):`, `fix:`, `ci:`, `build:`).

## Code of conduct
By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Questions
Open an issue, or contact Akin Kaldiroglu at akin@kaldiroglu.dev.
