# Instructor Run Sheet

*For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev*

## Before the room opens (setup)
1. Install the .NET 8 SDK (repo pins 8.0.x via `global.json`). Verify: `dotnet --version` → 8.0.x.
2. From the repo root: `dotnet build SecureCoding.NetBackend.sln` then `dotnet test` → expect **39 passing**.
3. Open the solution with the `Vulnerable` and `Fixed` projects side-by-side in the editor.
4. Two terminals, apps on pinned ports (no launch profile):
   - `ASPNETCORE_URLS=http://127.0.0.1:5101 dotnet run --project src/Vulnerable/Shop.Api --no-launch-profile`
   - `ASPNETCORE_URLS=http://127.0.0.1:5102 dotnet run --project src/Fixed/Shop.Api --no-launch-profile`
5. Keep `course/cheat-sheet.md` open in a third pane for copy-paste exploits.
6. For Ch10 (SSRF) have a throwaway internal server ready: `python3 -m http.server 9000`.

## Per-chapter rhythm (demo-heavy)
Read the `// CWE-XXX` line → fire the exploit on Vulnerable → show the Fixed diff (usually *less* code) → fire the same exploit on Fixed (blocked) → run that chapter's test filter green. Close on the one-line principle. Full speaker notes per chapter in `course/chapters/`.

## Day 1 — Injection · untrusted input · access control · output
| Time | Chapter |
|------|---------|
| 09:00 | Ch 0 — Orientation: secure coding vs appsec, the CWE spine, tour of the vuln app |
| 09:30 | Ch 1 — CWE-89 SQL injection |
| 10:25 | break |
| 10:40 | Ch 2 — CWE-915/20 mass assignment & validation *(Ch 15 / CWE-20 input-validation is the natural deep-dive here if time allows; otherwise self-study)* |
| 11:30 | Ch 3 — CWE-22 path traversal |
| 12:20 | lunch |
| 13:20 | Ch 4 — CWE-78 OS command injection |
| 14:10 | Ch 5 — CWE-79 output encoding |
| 15:00 | break |
| 15:15 | Ch 6 — CWE-639/862/863 access-control checks (extended) |
| 16:20 | Day-1 recap + "spot the bug" Q&A |
| 17:00 | End |

## Day 2 — Crypto · secrets · SSRF · deserialization · error & log hygiene
| Time | Chapter |
|------|---------|
| 09:00 | Day-1 recap |
| 09:15 | Ch 7 — CWE-327/916 crypto & password hashing |
| 10:20 | break |
| 10:35 | Ch 8 — CWE-330/338 insecure randomness |
| 11:20 | Ch 9 — CWE-798 hardcoded secrets |
| 12:10 | lunch |
| 13:10 | Ch 10 — CWE-918 SSRF |
| 13:55 | Ch 11 — CWE-502/611 deserialization & XXE |
| 14:45 | break |
| 15:00 | Ch 12 — CWE-209 error info exposure |
| 15:40 | Ch 13 — CWE-532 sensitive data in logs |
| 16:15 | Coda — analyzers + the secure-coding checklist |
| 16:45 | Wrap-up / Q&A |
| 17:00 | Ch 14 (Bonus) — CWE-117 log forging *(optional; extends the day to 17:30)* |
| 17:30 | End |

## Caveats to state out loud
- **SQLite, not SQL Server.** Chosen for zero setup; lessons are provider-agnostic. The CWE-89 demo shows the `OR 1=1` tautology (SQLite blocks stacked queries) — mention that SQL Server also enables stacked-query and `xp_cmdshell` payloads.
- **`X-User-Id` (Ch6) is a stand-in for a verified identity** (e.g. a JWT subject). It is NOT a real authentication pattern — never trust a raw client header for identity. The chapter teaches the *ownership check*, not auth design.
- **Ch4/Ch11 demos are POSIX/file-system specific** (macOS/Linux).

## Coda — make habits automatic
Teach the room that there are **two orthogonal scanners and they need both**:
- **SCA (dependencies):** `./scripts/check-vulnerable-packages.sh` (wraps `dotnet list package --vulnerable`) / Dependabot — finds known-CVE packages.
- **SAST (your code):** Roslyn security analyzers / Security Code Scan / GitHub CodeQL — finds weaknesses you wrote.

**Live demo (high impact — do it):** on the *same* `src/Vulnerable` project, run both back to back:
```bash
./scripts/check-vulnerable-packages.sh            # SCA  -> "No vulnerable packages." (deps are patched)
dotnet build src/Vulnerable/Shop.Api 2>&1 | grep -E "warning (CA|SCS)"   # SAST -> SQLi, command injection, path traversal, weak crypto...
```
The point to land: **"No vulnerable dependencies" does NOT mean "secure code."** A clean SCA report says nothing about the bugs in your own code — that is the entire reason this course exists. (Optional reinforcement: temporarily pin a known-bad package, e.g. `Newtonsoft.Json 12.0.3`, re-run the SCA script, watch it go red and exit non-zero, then revert.)
