# Chapter 3 — CWE-22: Path Traversal

**Time budget:** ~50 min · **CWE:** CWE-22 · **Files:** `src/Vulnerable/Shop.Api/Controllers/InvoicesController.cs` ↔ `src/Fixed/Shop.Api/Controllers/InvoicesController.cs` · test `tests/Shop.Tests/PathTraversalTests.cs`

## The weakness in one line
`Path.Combine(root, userInput)` does not collapse `..` segments, so the operating system resolves the final path outside the intended directory and into arbitrary parts of the filesystem.

## Live demo script
1. Open the Vulnerable `InvoicesController`. Read the `// CWE-22` comment aloud — note `Path.Combine(Root, name)` with no further validation.
2. Normal call: `GET /invoices?name=inv-1001.txt` → `Invoice 1001: $1200`. Show the temp directory structure: `invoices/` folder sits inside a `scc-vuln-files/` base directory that also contains a sibling `secret.txt`.
3. Fire the exploit: `GET /invoices?name=../secret.txt` → **`TOP-SECRET admin key`**. The OS resolved `invoices/../secret.txt` to the parent directory's file.
4. Open the Fixed `InvoicesController` side-by-side: `Path.GetFullPath` collapses the path, then `StartsWith(fullRoot)` (with trailing separator) ensures it remains inside the boundary. A traversal attempt gets a `400 Bad Request`.
5. Send the same `../secret.txt` payload to the Fixed app → `400 Bad Request`.
6. Run `dotnet test --filter FullyQualifiedName~PathTraversalTests` → green.

## Why it's exploitable (the mechanism)
`Path.Combine` is a string-concatenation helper — it joins path segments with the platform separator but does not resolve the logical path. The `..` token is meaningful to the OS file-system resolver, not to `Path.Combine`. When the combined string is handed to `File.Exists` or `File.ReadAllText`, the OS walks up the directory tree as instructed. The developer assumes `Combine` "stays inside" the root; it does not.

## The fix (and why it's usually less code)
Call `Path.GetFullPath` on the candidate path to let the OS collapse all `..` and `.` tokens into an absolute, canonical path. Then assert that the result starts with `Path.GetFullPath(Root) + Path.DirectorySeparatorChar` (the trailing separator is critical — without it, a directory named `invoices-other` would pass a naive prefix check). If the check fails, return `400` immediately; never reach the file-read call.

## The transferable principle
> **Resolve the path, then verify it's inside the boundary.**

## "But what about…" — anticipated questions
- **Q:** Why doesn't `Path.Combine` protect us — it already handles path separators? **A:** `Path.Combine` is purely a string-joining utility; it adds the platform separator between segments but does not resolve `..`. Only `Path.GetFullPath` (or equivalent OS call) collapses the navigation tokens.
- **Q:** Why does the Fixed code append `Path.DirectorySeparatorChar` to `fullRoot` before the `StartsWith` check? **A:** Without the trailing separator, a root of `/tmp/invoices` would incorrectly allow `/tmp/invoices-evil/secret.txt` because the string `"/tmp/invoices-evil/..."` starts with `"/tmp/invoices"`. The separator makes the boundary exact.
- **Q:** Could we just allow-list file names (e.g. `[A-Za-z0-9_-]+\.txt`)? **A:** Yes, and for narrow use-cases an allow-list is excellent defence-in-depth. However, it does not generalise — many real APIs must serve user-chosen filenames or paths. The containment check works for all inputs and is the broadly applicable pattern.
