# Chapter 9 — CWE-798: Hardcoded Credentials

**Time budget:** ~50 min · **CWE:** CWE-798 · **Files:** `src/Vulnerable/Shop.Api/Controllers/PartnerController.cs` ↔ `src/Fixed/Shop.Api/Controllers/PartnerController.cs` · test `tests/Shop.Tests/HardcodedSecretTests.cs`

## The weakness in one line

The partner API key is a compile-time `const` baked into the binary — anyone who can read the source code or decompile the assembly already has the secret, making it no longer a secret at all.

## Live demo script

1. Open the Vulnerable `PartnerController`. Read the `// CWE-798` comment aloud — point directly at `private const string ApiKey = "sk_live_51HARDCODEDpartnerKEY"`. Note it is `const`: it cannot be rotated without a code change and a new deployment.
2. Send `POST /partner/webhook` with header `X-Api-Key: sk_live_51HARDCODEDpartnerKEY` → 200 OK. The test `HardcodedSecretTests.Vulnerable_accepts_the_baked_in_key` does exactly this, using the value copied straight from the source file.
3. Ask: "If this application is open-source, or if someone obtains the compiled DLL and runs `dotnet-ildasm` or a decompiler, what do they have?" Answer: the live API key in plain text.
4. Open the Fixed `PartnerController` side-by-side: the `const` is gone; the constructor injects `IConfiguration`; the comparison reads `config["Partner:ApiKey"]`. The key exists only at runtime in the environment.
5. The test `Fixed_rejects_the_old_baked_in_key_and_accepts_the_configured_one` injects `"configured-test-key"` via `AddInMemoryCollection`, verifies the old baked-in value is now rejected (401), and verifies the configured value is accepted (200) — showing the secret is no longer in the binary.
6. Run `dotnet test --filter FullyQualifiedName~HardcodedSecretTests` → green.

## Why it's exploitable (the mechanism)

A `const` value is embedded as a literal string in the compiled IL and in the assembly's string heap; any decompiler (ILSpy, dnSpy, dotPeek) or the `strings` command exposes it immediately. Even in closed-source applications, compiled binaries are regularly extracted from Docker images, CI artefacts, or npm/NuGet packages. Once the key is in a git commit — even briefly, even in a private repo — it is in the repository history and may already have been cloned by automated secret-scanning bots that crawl GitHub in real time.

## The fix (and why it's usually less code)

Remove the `const` and inject `IConfiguration`; the key now lives in an environment variable, a secrets manager (Azure Key Vault, AWS Secrets Manager), or `dotnet user-secrets` for local development. The fix reduces binary-embedded secrets to zero and makes rotation a configuration change rather than a code change. The comparison logic is identical — one fewer line of code and zero secrets in the source tree.

## The transferable principle

> **Secrets never belong in source.**

## "But what about…" — anticipated questions

- **Q:** The binary is private — does it really matter if the key is in it? **A:** Yes. Binaries leak through Docker image layers, CI pipeline artefacts, package registries, developer laptops, and decommissioned servers. Treat the binary as public. Additionally, the key in source code means it travels through every developer's workstation, every CI runner, and every git clone — that is a very large attack surface for what should be a one-server secret.
- **Q:** How should developers store secrets locally without hardcoding them? **A:** Use `dotnet user-secrets` (`dotnet user-secrets set "Partner:ApiKey" "my-dev-key"`). The value is stored in a JSON file in the user's home directory, outside the project tree, and never committed to git. For CI/CD, use the pipeline's secret store (GitHub Actions secrets, Azure DevOps variable groups). For production, use a managed secrets service and inject at runtime via environment variables or the configuration provider.
- **Q:** What if the key is already in git history? **A:** Treat it as compromised immediately and rotate it. Remove the literal from history using `git filter-repo` (not `git filter-branch`), but rotation must happen first and in parallel — anyone who cloned the repo before the rewrite already has the old key. Git history rewrites do not make a leaked secret safe; only rotation does.
