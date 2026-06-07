# Secure Coding Course — Plan 2: Day 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the seven Day-2 secure-coding weakness chapters to the existing twin-project solution, each proven by an exploit test.

**Architecture:** Continues Plan 1. Two ASP.NET Core 8 Web API projects — `Vulnerable` (root namespace `dev.kaldiroglu.SecureCoding.Shop.Vulnerable`) and `Fixed` (`...Shop.Fixed`) — share identical routes over EF Core + SQLite. One xUnit project (`dev.kaldiroglu.SecureCoding.Shop.Tests`) references both via `WebApplicationFactory` (`VulnerableFactory`/`FixedFactory`) on isolated in-memory SQLite. Each new chapter adds a controller pair plus a differential exploit test. Weaknesses are tagged `// CWE-XXX`.

**Tech Stack:** .NET 8, C# 12, ASP.NET Core controllers, EF Core 8 + SQLite, xUnit, Microsoft.AspNetCore.Mvc.Testing, Newtonsoft.Json (Ch11), ASP.NET Core Identity `PasswordHasher` + Data Protection API (Ch7, both in the shared framework).

**Companion spec:** `docs/superpowers/specs/2026-06-07-secure-coding-dotnet-course-design.md`
**Prerequisite:** Plan 1 is merged to `main` (foundation + Day-1 chapters, 13 tests green).

---

## Conventions (carry over from Plan 1)
- **Distinct namespaces:** Vulnerable controllers live in `dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers`; Fixed in `dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers`. Domain/helper types use the matching `.Domain` namespace.
- **TDD per task:** write the failing test → confirm RED → implement vulnerable → implement fixed → confirm GREEN → run full suite → commit.
- **Do not modify** Day-1 controllers. Program.cs edits are allowed where a chapter needs DI registration (called out explicitly).
- **Shell rule:** the repo path contains a space (`Secure Code`); never backslash-escape it — use relative paths or double-quote absolute paths.
- Start on a feature branch off `main` (e.g. `feat/plan2-day2`); do not implement on `main`.

## File Structure (new files only)
```
src/{Vulnerable,Fixed}/Shop.Api/Controllers/
   CryptoController.cs          # Ch7  CWE-327/916
   AccountRecoveryController.cs # Ch8  CWE-330/338
   PartnerController.cs         # Ch9  CWE-798
   AvatarController.cs          # Ch10 CWE-918
   ImportController.cs          # Ch11 CWE-502 / 611
   DiagnosticsController.cs     # Ch12 CWE-209
   SessionController.cs         # Ch13 CWE-532
src/Vulnerable/Shop.Api/Domain/ImportGadget.cs   # Ch11 (vulnerable only)
tests/Shop.Tests/
   CryptoTests.cs  RandomnessTests.cs  HardcodedSecretTests.cs
   SsrfTests.cs  DeserializationTests.cs  ErrorExposureTests.cs  LoggingTests.cs
   ListLoggerProvider.cs        # Ch13 test helper
```

---

## Task 1: Chapter 7 — CWE-327/916 Broken crypto & password hashing

Two endpoints per project: password hashing and symmetric encryption.

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/CryptoController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/CryptoController.cs`
- Modify: `src/Fixed/Shop.Api/Program.cs` (register Data Protection)
- Create: `tests/Shop.Tests/CryptoTests.cs`

- [ ] **Step 1: Write the failing tests.** Create `tests/Shop.Tests/CryptoTests.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class CryptoTests
{
    public record HashResponse(string Hash);
    public record CipherResponse(string Ciphertext);

    [Fact]
    public async Task Vulnerable_password_hash_is_unsalted_md5()
    {
        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var h1 = (await (await c.PostAsJsonAsync("/crypto/hash", new { password = "hunter2" })).Content.ReadFromJsonAsync<HashResponse>())!.Hash;
        var h2 = (await (await c.PostAsJsonAsync("/crypto/hash", new { password = "hunter2" })).Content.ReadFromJsonAsync<HashResponse>())!.Hash;
        var md5 = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes("hunter2"))).ToLowerInvariant();
        Assert.Equal(h1, h2);     // deterministic -> rainbow-table-able
        Assert.Equal(md5, h1);    // it's just MD5
    }

    [Fact]
    public async Task Fixed_password_hash_is_salted()
    {
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var h1 = (await (await c.PostAsJsonAsync("/crypto/hash", new { password = "hunter2" })).Content.ReadFromJsonAsync<HashResponse>())!.Hash;
        var h2 = (await (await c.PostAsJsonAsync("/crypto/hash", new { password = "hunter2" })).Content.ReadFromJsonAsync<HashResponse>())!.Hash;
        Assert.NotEqual(h1, h2);  // per-hash random salt
    }

    [Fact]
    public async Task Vulnerable_ecb_leaks_identical_blocks()
    {
        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        // 32 bytes = two identical 16-byte blocks
        var ct = (await (await c.PostAsJsonAsync("/crypto/encrypt", new { plaintext = "YELLOW_SUBMARINEYELLOW_SUBMARINE" })).Content.ReadFromJsonAsync<CipherResponse>())!.Ciphertext;
        var bytes = Convert.FromBase64String(ct);
        Assert.Equal(bytes[..16], bytes[16..32]);   // ECB: equal plaintext blocks -> equal ciphertext blocks
    }

    [Fact]
    public async Task Fixed_encryption_is_non_deterministic()
    {
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var ct1 = (await (await c.PostAsJsonAsync("/crypto/encrypt", new { plaintext = "YELLOW_SUBMARINEYELLOW_SUBMARINE" })).Content.ReadFromJsonAsync<CipherResponse>())!.Ciphertext;
        var ct2 = (await (await c.PostAsJsonAsync("/crypto/encrypt", new { plaintext = "YELLOW_SUBMARINEYELLOW_SUBMARINE" })).Content.ReadFromJsonAsync<CipherResponse>())!.Ciphertext;
        Assert.NotEqual(ct1, ct2);   // random subkey/IV each call
    }
}
```

- [ ] **Step 2: Run to verify FAIL.** `dotnet test --filter FullyQualifiedName~CryptoTests` → expect FAIL (routes 404). Confirm before implementing.

- [ ] **Step 3: VULNERABLE controller.** Create `src/Vulnerable/Shop.Api/Controllers/CryptoController.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("crypto")]
public class CryptoController : ControllerBase
{
    public record HashRequest(string Password);
    public record EncryptRequest(string Plaintext);

    // CWE-916: unsalted, fast hash — trivially cracked / rainbow-tabled.
    [HttpPost("hash")]
    public IActionResult Hash([FromBody] HashRequest req)
    {
        var hex = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(req.Password))).ToLowerInvariant();
        return Ok(new { Hash = hex });
    }

    // CWE-327: AES in ECB mode — identical plaintext blocks produce identical ciphertext blocks.
    [HttpPost("encrypt")]
    public IActionResult Encrypt([FromBody] EncryptRequest req)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes("0123456789ABCDEF"); // hardcoded 128-bit key (also bad)
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        var data = Encoding.UTF8.GetBytes(req.Plaintext);
        var ct = aes.EncryptEcb(data, PaddingMode.PKCS7);
        return Ok(new { Ciphertext = Convert.ToBase64String(ct) });
    }
}
```

- [ ] **Step 4: Register Data Protection in the Fixed app.** Edit `src/Fixed/Shop.Api/Program.cs`: add `builder.Services.AddDataProtection();` immediately after the `builder.Services.AddControllers();` line. (Namespace `Microsoft.AspNetCore.DataProtection` is in the shared framework; `AddDataProtection` resolves via implicit usings or add `using Microsoft.AspNetCore.DataProtection;`.)

- [ ] **Step 5: FIXED controller.** Create `src/Fixed/Shop.Api/Controllers/CryptoController.cs`:
```csharp
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("crypto")]
public class CryptoController(IDataProtectionProvider dp) : ControllerBase
{
    public record HashRequest(string Password);
    public record EncryptRequest(string Plaintext);

    private static readonly PasswordHasher<object> Hasher = new();
    private static readonly object Dummy = new();

    // FIXED: PBKDF2 via ASP.NET Core Identity's PasswordHasher — per-hash random salt + work factor.
    [HttpPost("hash")]
    public IActionResult Hash([FromBody] HashRequest req) =>
        Ok(new { Hash = Hasher.HashPassword(Dummy, req.Password) });

    // FIXED: never hand-roll crypto — use the Data Protection API (authenticated, random subkeys).
    [HttpPost("encrypt")]
    public IActionResult Encrypt([FromBody] EncryptRequest req)
    {
        var protector = dp.CreateProtector("shop.crypto.demo");
        return Ok(new { Ciphertext = protector.Protect(req.Plaintext) });
    }
}
```

- [ ] **Step 6: Run to verify PASS.** `dotnet test --filter FullyQualifiedName~CryptoTests` → expect PASS (4 tests). Then full `dotnet test` → confirm no regressions.

- [ ] **Step 7: Commit.**
```bash
git add -A
git commit -m "feat(ch7): CWE-327/916 crypto & password hashing vulnerable/fixed + tests"
```

---

## Task 2: Chapter 8 — CWE-330/338 Insecure randomness (password-reset token)

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/AccountRecoveryController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/AccountRecoveryController.cs`
- Create: `tests/Shop.Tests/RandomnessTests.cs`

The vulnerable controller seeds `System.Random` with a fixed/low-entropy constant on every request, so every reset token is fully predictable (here, identical). Teaching note: even `new Random()` (time-seeded) is predictable to an attacker who knows roughly when the request occurred — the fixed seed just makes the determinism visible and testable.

- [ ] **Step 1: Write the failing tests.** Create `tests/Shop.Tests/RandomnessTests.cs`:
```csharp
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class RandomnessTests
{
    public record TokenResponse(string Token);

    private const int Seed = 20260607;

    [Fact]
    public async Task Vulnerable_token_is_predictable()
    {
        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var t1 = (await c.GetFromJsonAsync<TokenResponse>("/account/reset-token"))!.Token;
        var t2 = (await c.GetFromJsonAsync<TokenResponse>("/account/reset-token"))!.Token;

        // Attacker reproduces the token knowing the seed (System.Random is fully determined by it).
        var rng = new Random(Seed);
        var bytes = new byte[16];
        rng.NextBytes(bytes);
        var predicted = Convert.ToHexString(bytes).ToLowerInvariant();

        Assert.Equal(t1, t2);          // re-seeded each call -> identical
        Assert.Equal(predicted, t1);   // and predictable from the seed
    }

    [Fact]
    public async Task Fixed_tokens_are_unpredictable_and_unique()
    {
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var t1 = (await c.GetFromJsonAsync<TokenResponse>("/account/reset-token"))!.Token;
        var t2 = (await c.GetFromJsonAsync<TokenResponse>("/account/reset-token"))!.Token;
        Assert.NotEqual(t1, t2);
        Assert.True(Convert.FromHexString(t1).Length >= 32);   // >= 256 bits
    }
}
```

- [ ] **Step 2: Run to verify FAIL.** `dotnet test --filter FullyQualifiedName~RandomnessTests` → expect FAIL (route 404). Confirm.

- [ ] **Step 3: VULNERABLE controller.** Create `src/Vulnerable/Shop.Api/Controllers/AccountRecoveryController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("account")]
public class AccountRecoveryController : ControllerBase
{
    // CWE-330/338: System.Random seeded with a fixed/low-entropy value — output is fully predictable.
    [HttpGet("reset-token")]
    public IActionResult ResetToken()
    {
        var rng = new Random(20260607);
        var bytes = new byte[16];
        rng.NextBytes(bytes);
        return Ok(new { Token = Convert.ToHexString(bytes).ToLowerInvariant() });
    }
}
```

- [ ] **Step 4: FIXED controller.** Create `src/Fixed/Shop.Api/Controllers/AccountRecoveryController.cs`:
```csharp
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("account")]
public class AccountRecoveryController : ControllerBase
{
    // FIXED: security tokens come from a CSPRNG.
    [HttpGet("reset-token")]
    public IActionResult ResetToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Ok(new { Token = Convert.ToHexString(bytes).ToLowerInvariant() });
    }
}
```

- [ ] **Step 5: Run to verify PASS.** `dotnet test --filter FullyQualifiedName~RandomnessTests` → expect PASS (2). Then full `dotnet test`.

- [ ] **Step 6: Commit.**
```bash
git add -A
git commit -m "feat(ch8): CWE-330/338 insecure randomness vulnerable/fixed reset token + tests"
```

---

## Task 3: Chapter 9 — CWE-798 Hardcoded secrets in code

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/PartnerController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/PartnerController.cs`
- Create: `tests/Shop.Tests/HardcodedSecretTests.cs`

A partner webhook authenticates with an API key. Vulnerable compares against a compile-time `const` (extractable from the binary). Fixed compares against a value from `IConfiguration` (supplied by the deployer, not in source).

- [ ] **Step 1: Write the failing tests.** Create `tests/Shop.Tests/HardcodedSecretTests.cs`:
```csharp
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class HardcodedSecretTests
{
    // This value is discoverable by anyone who reads the Vulnerable source/binary.
    private const string LeakedKey = "sk_live_51HARDCODEDpartnerKEY";

    private static HttpRequestMessage Webhook(string key)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/partner/webhook");
        req.Headers.Add("X-Api-Key", key);
        return req;
    }

    [Fact]
    public async Task Vulnerable_accepts_the_baked_in_key()
    {
        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var resp = await c.SendAsync(Webhook(LeakedKey));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);   // secret is in the binary -> not secret
    }

    [Fact]
    public async Task Fixed_rejects_the_old_baked_in_key_and_accepts_the_configured_one()
    {
        using var f = new FixedFactory();
        using var configured = f.WithWebHostBuilder(b =>
            b.ConfigureAppConfiguration((_, cfg) =>
                cfg.AddInMemoryCollection(new Dictionary<string, string?> { ["Partner:ApiKey"] = "configured-test-key" })));
        var c = configured.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await c.SendAsync(Webhook(LeakedKey))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Webhook("configured-test-key"))).StatusCode);
    }
}
```

- [ ] **Step 2: Run to verify FAIL.** `dotnet test --filter FullyQualifiedName~HardcodedSecretTests` → expect FAIL (route 404). Confirm.

- [ ] **Step 3: VULNERABLE controller.** Create `src/Vulnerable/Shop.Api/Controllers/PartnerController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("partner")]
public class PartnerController : ControllerBase
{
    // CWE-798: secret hardcoded in source — present in the compiled binary, discoverable by anyone.
    private const string ApiKey = "sk_live_51HARDCODEDpartnerKEY";

    [HttpPost("webhook")]
    public IActionResult Webhook()
    {
        var provided = Request.Headers["X-Api-Key"].ToString();
        return provided == ApiKey ? Ok() : Unauthorized();
    }
}
```

- [ ] **Step 4: FIXED controller.** Create `src/Fixed/Shop.Api/Controllers/PartnerController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("partner")]
public class PartnerController(IConfiguration config) : ControllerBase
{
    // FIXED: the secret comes from configuration (env var / user-secrets / vault), never from source.
    [HttpPost("webhook")]
    public IActionResult Webhook()
    {
        var expected = config["Partner:ApiKey"];
        var provided = Request.Headers["X-Api-Key"].ToString();
        if (string.IsNullOrEmpty(expected) || provided != expected) return Unauthorized();
        return Ok();
    }
}
```

- [ ] **Step 5: Run to verify PASS.** `dotnet test --filter FullyQualifiedName~HardcodedSecretTests` → expect PASS (2). Then full `dotnet test`.

- [ ] **Step 6: Commit.**
```bash
git add -A
git commit -m "feat(ch9): CWE-798 hardcoded secrets vulnerable/fixed partner webhook + tests"
```

---

## Task 4: Chapter 10 — CWE-918 SSRF (avatar import)

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/AvatarController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/AvatarController.cs`
- Create: `tests/Shop.Tests/SsrfTests.cs`

The endpoint imports an avatar from a user-supplied URL. Vulnerable fetches any URL (so an attacker reaches internal services). Fixed allow-lists outbound destinations and rejects loopback/internal hosts.

> The test stands up a real loopback `HttpListener` representing an "internal service". The app's outbound `HttpClient` makes a real OS socket call to it (the in-memory test server only affects inbound requests), so the SSRF is genuinely demonstrated.

- [ ] **Step 1: Write the failing tests.** Create `tests/Shop.Tests/SsrfTests.cs`:
```csharp
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class SsrfTests
{
    public record ImportResponse(string Fetched);

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Fact]
    public async Task Vulnerable_import_reaches_internal_service()
    {
        var port = FreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        var serve = Task.Run(async () =>
        {
            var ctx = await listener.GetContextAsync();
            var bytes = Encoding.UTF8.GetBytes("INTERNAL-SECRET-DATA");
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            ctx.Response.Close();
        });

        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsJsonAsync("/avatar/import", new { url = $"http://127.0.0.1:{port}/" });
        var body = await resp.Content.ReadFromJsonAsync<ImportResponse>();
        await serve;
        listener.Stop();

        Assert.Contains("INTERNAL-SECRET-DATA", body!.Fetched);   // SSRF: server fetched an internal URL
    }

    [Fact]
    public async Task Fixed_import_blocks_internal_targets()
    {
        var port = FreePort();
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsJsonAsync("/avatar/import", new { url = $"http://127.0.0.1:{port}/" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);  // loopback not on the allow-list
    }
}
```

- [ ] **Step 2: Run to verify FAIL.** `dotnet test --filter FullyQualifiedName~SsrfTests` → expect FAIL (route 404). Confirm.

- [ ] **Step 3: VULNERABLE controller.** Create `src/Vulnerable/Shop.Api/Controllers/AvatarController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("avatar")]
public class AvatarController : ControllerBase
{
    public record ImportRequest(string Url);

    // CWE-918: SSRF — the server fetches whatever URL the client supplies, including internal hosts.
    [HttpPost("import")]
    public async Task<IActionResult> Import([FromBody] ImportRequest req)
    {
        using var http = new HttpClient();
        var content = await http.GetStringAsync(req.Url);
        return Ok(new { Fetched = content });
    }
}
```

- [ ] **Step 4: FIXED controller.** Create `src/Fixed/Shop.Api/Controllers/AvatarController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("avatar")]
public class AvatarController : ControllerBase
{
    public record ImportRequest(string Url);

    // FIXED: validate the destination against an allow-list; never let input pick where the server connects.
    [HttpPost("import")]
    public async Task<IActionResult> Import([FromBody] ImportRequest req)
    {
        if (!Uri.TryCreate(req.Url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return BadRequest("Invalid URL.");
        if (uri.IsLoopback || !uri.Host.EndsWith(".example.com", StringComparison.OrdinalIgnoreCase))
            return BadRequest("Destination not allowed.");

        using var http = new HttpClient();
        var content = await http.GetStringAsync(uri);
        return Ok(new { Fetched = content });
    }
}
```

- [ ] **Step 5: Run to verify PASS.** `dotnet test --filter FullyQualifiedName~SsrfTests` → expect PASS (2). Then full `dotnet test`.

- [ ] **Step 6: Commit.**
```bash
git add -A
git commit -m "feat(ch10): CWE-918 SSRF vulnerable/fixed avatar import + tests"
```

---

## Task 5: Chapter 11 — CWE-502 (+611 XXE) Unsafe deserialization

**Files:**
- Modify: `src/Vulnerable/Shop.Api/Shop.Api.csproj` and `src/Fixed/Shop.Api/Shop.Api.csproj` (add Newtonsoft.Json)
- Create: `src/Vulnerable/Shop.Api/Domain/ImportGadget.cs`
- Create: `src/Vulnerable/Shop.Api/Controllers/ImportController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/ImportController.cs`
- Create: `tests/Shop.Tests/DeserializationTests.cs`

Two demos: (a) JSON deserialization with `TypeNameHandling.All` instantiating an attacker-chosen type (the `ImportGadget` writes a sentinel file on property-set — a stand-in for RCE); (b) XXE via a DTD external entity reading a local file.

- [ ] **Step 1: Add Newtonsoft.Json to both API projects.**
```bash
dotnet add src/Vulnerable/Shop.Api/Shop.Api.csproj package Newtonsoft.Json --version 13.0.3
dotnet add src/Fixed/Shop.Api/Shop.Api.csproj package Newtonsoft.Json --version 13.0.3
```

- [ ] **Step 2: Write the failing tests.** Create `tests/Shop.Tests/DeserializationTests.cs`:
```csharp
using System.Net;
using System.Net.Http;
using System.Text;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class DeserializationTests
{
    private static StringContent Json(string s) => new(s, Encoding.UTF8, "application/json");
    private static StringContent Xml(string s) => new(s, Encoding.UTF8, "application/xml");

    [Fact]
    public async Task Vulnerable_json_instantiates_attacker_type()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-deser-vuln.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        // $type drives construction of an arbitrary type; the gadget's setter has a side effect.
        var payload = "{\"$type\":\"dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain.ImportGadget, dev.kaldiroglu.SecureCoding.Shop.Vulnerable\",\"Trigger\":\""
                      + sentinel.Replace("\\", "\\\\") + "\"}";

        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        await c.PostAsync("/import/json", Json(payload));

        Assert.True(File.Exists(sentinel));   // attacker-chosen type was constructed
        File.Delete(sentinel);
    }

    [Fact]
    public async Task Fixed_json_ignores_type_directives()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-deser-fixed.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = "{\"$type\":\"dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain.ImportGadget, dev.kaldiroglu.SecureCoding.Shop.Vulnerable\",\"Trigger\":\""
                      + sentinel.Replace("\\", "\\\\") + "\"}";

        using var f = new FixedFactory();
        var c = f.CreateClient();
        await c.PostAsync("/import/json", Json(payload));

        Assert.False(File.Exists(sentinel));  // $type ignored; bound to a fixed DTO
    }

    [Fact]
    public async Task Vulnerable_xml_expands_external_entity()
    {
        var secret = Path.Combine(Path.GetTempPath(), "scc-xxe-secret.txt");
        File.WriteAllText(secret, "XXE-SECRET-9999");
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://" + secret + "\">]><foo>&xxe;</foo>";

        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var body = await (await c.PostAsync("/import/xml", Xml(xml))).Content.ReadAsStringAsync();

        Assert.Contains("XXE-SECRET-9999", body);   // external entity read a local file
    }

    [Fact]
    public async Task Fixed_xml_rejects_dtd()
    {
        var secret = Path.Combine(Path.GetTempPath(), "scc-xxe-secret.txt");
        File.WriteAllText(secret, "XXE-SECRET-9999");
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://" + secret + "\">]><foo>&xxe;</foo>";

        using var f = new FixedFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsync("/import/xml", Xml(xml));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);   // DTD prohibited
    }
}
```

- [ ] **Step 3: Run to verify FAIL.** `dotnet test --filter FullyQualifiedName~DeserializationTests` → expect FAIL (routes 404). Confirm.

- [ ] **Step 4: Create the gadget (Vulnerable only).** `src/Vulnerable/Shop.Api/Domain/ImportGadget.cs`:
```csharp
namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;

// A deserialization "gadget": setting a property triggers a side effect. With TypeNameHandling.All,
// an attacker chooses this type via "$type" and drives the setter. Stands in for RCE in the demo.
public class ImportGadget
{
    private string _trigger = "";
    public string Trigger
    {
        get => _trigger;
        set { _trigger = value; System.IO.File.WriteAllText(value, "pwned-by-deser"); }
    }
}
```

- [ ] **Step 5: VULNERABLE controller.** `src/Vulnerable/Shop.Api/Controllers/ImportController.cs`:
```csharp
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("import")]
public class ImportController : ControllerBase
{
    // CWE-502: TypeNameHandling.All lets the payload pick which .NET type to instantiate.
    // Bind the raw JSON via System.Text.Json, then re-deserialize with the vulnerable Newtonsoft settings.
    [HttpPost("json")]
    public IActionResult Json([FromBody] System.Text.Json.JsonElement raw)
    {
        JsonConvert.DeserializeObject(raw.GetRawText(),
            new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
        return Ok();
    }

    // CWE-611: XML parser with DTD processing and an external resolver enabled.
    // NOTE: async body read — ASP.NET Core 8 disallows synchronous IO (AllowSynchronousIO=false).
    [HttpPost("xml")]
    public async Task<IActionResult> Xml()
    {
        using var sr = new StreamReader(Request.Body);
        var body = await sr.ReadToEndAsync();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
        using var reader = XmlReader.Create(new StringReader(body), settings);
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        doc.Load(reader);
        return Ok(doc.DocumentElement?.InnerText);
    }
}
```
> Note: binding `[FromBody] JsonElement` reliably captures the raw JSON (including `$type`) regardless of model binding; `raw.GetRawText()` feeds the original payload to the vulnerable `TypeNameHandling.All` deserialize. Both projects reference Newtonsoft.Json — the lesson is that the *fix is leaving `TypeNameHandling` at its safe default*, not switching libraries.

- [ ] **Step 6: FIXED controller.** `src/Fixed/Shop.Api/Controllers/ImportController.cs`:
```csharp
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("import")]
public class ImportController : ControllerBase
{
    public record ImportDto(string Name);

    // FIXED: deserialize into a known DTO with default settings — "$type" is ignored, no type confusion.
    [HttpPost("json")]
    public IActionResult Json([FromBody] System.Text.Json.JsonElement raw)
    {
        JsonConvert.DeserializeObject<ImportDto>(raw.GetRawText());   // TypeNameHandling.None (default)
        return Ok();
    }

    // FIXED: prohibit DTDs and disable the external resolver (this is also the .NET 8 default).
    // NOTE: async body read — ASP.NET Core 8 disallows synchronous IO (AllowSynchronousIO=false).
    [HttpPost("xml")]
    public async Task<IActionResult> Xml()
    {
        using var sr = new StreamReader(Request.Body);
        var body = await sr.ReadToEndAsync();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new StringReader(body), settings);
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(reader);
            return Ok(doc.DocumentElement?.InnerText);
        }
        catch (XmlException)
        {
            return BadRequest("DTD / external entities are not allowed.");
        }
    }
}
```

- [ ] **Step 7: Run to verify PASS.** `dotnet test --filter FullyQualifiedName~DeserializationTests` → expect PASS (4). Then full `dotnet test`.

- [ ] **Step 8: Commit.**
```bash
git add -A
git commit -m "feat(ch11): CWE-502/611 unsafe deserialization + XXE vulnerable/fixed + tests"
```

---

## Task 6: Chapter 12 — CWE-209 Information exposure via errors

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/DiagnosticsController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/DiagnosticsController.cs`
- Create: `tests/Shop.Tests/ErrorExposureTests.cs`

An operation fails. Vulnerable returns the full exception (stack trace + a sensitive connection string in the message). Fixed returns a generic `ProblemDetails` and keeps details server-side.

- [ ] **Step 1: Write the failing tests.** Create `tests/Shop.Tests/ErrorExposureTests.cs`:
```csharp
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class ErrorExposureTests
{
    [Fact]
    public async Task Vulnerable_error_leaks_internals()
    {
        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var body = await (await c.GetAsync("/diagnostics/run")).Content.ReadAsStringAsync();
        Assert.Contains("P@ssw0rd-SECRET", body);          // connection string leaked
        Assert.Contains("InvalidOperationException", body); // exception type / stack trace leaked
    }

    [Fact]
    public async Task Fixed_error_is_generic()
    {
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var body = await (await c.GetAsync("/diagnostics/run")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("P@ssw0rd-SECRET", body);
        Assert.DoesNotContain("InvalidOperationException", body);
        Assert.Contains("An unexpected error occurred", body);
    }
}
```

- [ ] **Step 2: Run to verify FAIL.** `dotnet test --filter FullyQualifiedName~ErrorExposureTests` → expect FAIL (route 404). Confirm.

- [ ] **Step 3: VULNERABLE controller.** `src/Vulnerable/Shop.Api/Controllers/DiagnosticsController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("diagnostics")]
public class DiagnosticsController : ControllerBase
{
    // CWE-209: returns the full exception (stack trace + sensitive message) to the caller.
    [HttpGet("run")]
    public IActionResult Run()
    {
        try
        {
            throw new InvalidOperationException(
                "DB connection failed: Server=db;User=sa;Password=P@ssw0rd-SECRET");
        }
        catch (Exception ex)
        {
            return StatusCode(500, ex.ToString());
        }
    }
}
```

- [ ] **Step 4: FIXED controller.** `src/Fixed/Shop.Api/Controllers/DiagnosticsController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("diagnostics")]
public class DiagnosticsController(ILogger<DiagnosticsController> logger) : ControllerBase
{
    // FIXED: log details server-side; return a generic ProblemDetails to the caller.
    [HttpGet("run")]
    public IActionResult Run()
    {
        try
        {
            throw new InvalidOperationException(
                "DB connection failed: Server=db;User=sa;Password=P@ssw0rd-SECRET");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Diagnostics run failed");
            return StatusCode(500, new ProblemDetails
            {
                Title = "An unexpected error occurred.",
                Status = 500
            });
        }
    }
}
```

- [ ] **Step 5: Run to verify PASS.** `dotnet test --filter FullyQualifiedName~ErrorExposureTests` → expect PASS (2). Then full `dotnet test`.

- [ ] **Step 6: Commit.**
```bash
git add -A
git commit -m "feat(ch12): CWE-209 error info exposure vulnerable/fixed diagnostics + tests"
```

---

## Task 7: Chapter 13 — CWE-532 Sensitive data in logs

**Files:**
- Create: `tests/Shop.Tests/ListLoggerProvider.cs`
- Create: `src/Vulnerable/Shop.Api/Controllers/SessionController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/SessionController.cs`
- Create: `tests/Shop.Tests/LoggingTests.cs`

A login endpoint. Vulnerable logs the password; Fixed logs only the username. The test injects an in-memory logger provider and inspects captured messages.

- [ ] **Step 1: Create the test logger provider.** `tests/Shop.Tests/ListLoggerProvider.cs`:
```csharp
using System;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public sealed class ListLoggerProvider : ILoggerProvider
{
    public readonly ConcurrentQueue<string> Messages = new();
    public ILogger CreateLogger(string categoryName) => new ListLogger(Messages);
    public void Dispose() { }

    private sealed class ListLogger(ConcurrentQueue<string> sink) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => sink.Enqueue(formatter(state, exception));
    }
}
```

- [ ] **Step 2: Write the failing tests.** `tests/Shop.Tests/LoggingTests.cs`:
```csharp
using System.Linq;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class LoggingTests
{
    private const string Password = "hunter2-SECRET";

    [Fact]
    public async Task Vulnerable_login_logs_the_password()
    {
        var sink = new ListLoggerProvider();
        using var f = new VulnerableFactory();
        using var configured = f.WithWebHostBuilder(b =>
            b.ConfigureLogging(lb => { lb.ClearProviders(); lb.AddProvider(sink); lb.SetMinimumLevel(LogLevel.Information); }));
        var c = configured.CreateClient();

        await c.PostAsJsonAsync("/session/login", new { username = "alice", password = Password });

        Assert.Contains(sink.Messages, m => m.Contains(Password));   // password leaked into logs
    }

    [Fact]
    public async Task Fixed_login_does_not_log_the_password()
    {
        var sink = new ListLoggerProvider();
        using var f = new FixedFactory();
        using var configured = f.WithWebHostBuilder(b =>
            b.ConfigureLogging(lb => { lb.ClearProviders(); lb.AddProvider(sink); lb.SetMinimumLevel(LogLevel.Information); }));
        var c = configured.CreateClient();

        await c.PostAsJsonAsync("/session/login", new { username = "alice", password = Password });

        Assert.DoesNotContain(sink.Messages, m => m.Contains(Password));
        Assert.Contains(sink.Messages, m => m.Contains("alice"));    // username is fine to log
    }
}
```

- [ ] **Step 3: Run to verify FAIL.** `dotnet test --filter FullyQualifiedName~LoggingTests` → expect FAIL (route 404). Confirm.

- [ ] **Step 4: VULNERABLE controller.** `src/Vulnerable/Shop.Api/Controllers/SessionController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("session")]
public class SessionController(ILogger<SessionController> logger) : ControllerBase
{
    public record LoginRequest(string Username, string Password);

    // CWE-532: logs the credential. Anyone with log access now has the password.
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        logger.LogInformation("Login attempt: user={User} password={Password}", req.Username, req.Password);
        return Ok();
    }
}
```

- [ ] **Step 5: FIXED controller.** `src/Fixed/Shop.Api/Controllers/SessionController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("session")]
public class SessionController(ILogger<SessionController> logger) : ControllerBase
{
    public record LoginRequest(string Username, string Password);

    // FIXED: log only non-sensitive context; never the password/token.
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        logger.LogInformation("Login attempt for user {User}", req.Username);
        return Ok();
    }
}
```

- [ ] **Step 6: Run to verify PASS.** `dotnet test --filter FullyQualifiedName~LoggingTests` → expect PASS (2). Then full `dotnet test`.

- [ ] **Step 7: Commit.**
```bash
git add -A
git commit -m "feat(ch13): CWE-532 sensitive data in logs vulnerable/fixed login + tests"
```

---

## Task 8: Update README.md and Test.md with Day-2 coverage

**Files:**
- Modify: `README.md`
- Modify: `Test.md`

- [ ] **Step 1:** In `README.md`, replace the "Day-1 weaknesses implemented:" bullet block under **Functional properties** so it reads (Day-1 line unchanged, add a Day-2 line):
```markdown
- Day-1 weaknesses: CWE-89 (SQL injection), CWE-915/20 (mass assignment),
  CWE-22 (path traversal), CWE-78 (command injection), CWE-79 (output encoding),
  CWE-639/862/863 (broken access-control checks).
- Day-2 weaknesses: CWE-327/916 (broken crypto & password hashing), CWE-330/338
  (insecure randomness), CWE-798 (hardcoded secrets), CWE-918 (SSRF), CWE-502/611
  (unsafe deserialization & XXE), CWE-209 (error info exposure), CWE-532 (sensitive data in logs).
```

- [ ] **Step 2:** In `Test.md`, append these rows to the inventory table (after the Day-1 rows), under a new "Inventory (Day 2)" subheading:
```markdown
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
```

- [ ] **Step 3: Commit.**
```bash
git add README.md Test.md
git commit -m "docs: add Day-2 coverage to README.md and Test.md"
```

---

## Task 9: Full-suite verification

- [ ] **Step 1: Run the entire suite.** `dotnet test SecureCoding.NetBackend.sln`
Expected: PASS — Day-1's 13 tests plus the Day-2 tests (CryptoTests 4 + RandomnessTests 2 + HardcodedSecretTests 2 + SsrfTests 2 + DeserializationTests 4 + ErrorExposureTests 2 + LoggingTests 2 = 18), **31 total**, 0 failures.

- [ ] **Step 2: Confirm CWE tags are present.** Run `grep -rn "CWE-" src/` and confirm every Day-2 controller carries its `// CWE-XXX` tag.

- [ ] **Step 3: Final commit (if any docs touched).**
```bash
git add -A
git commit -m "test: verify full Day-1 + Day-2 suite green" --allow-empty
```

---

## Self-Review notes
- **Spec coverage (Day 2):** every Day-2 chapter in the spec is implemented — CWE-327/916 (Task 1), CWE-330/338 (Task 2), CWE-798 (Task 3), CWE-918 (Task 4), CWE-502/611 (Task 5), CWE-209 (Task 6), CWE-532 (Task 7) — each with vulnerable code, fixed code, and a differential exploit test. The coda (analyzers) is a teaching segment with no code, covered by Plan 3.
- **New dependencies:** Newtonsoft.Json (Ch11) added to both API projects; `PasswordHasher` and Data Protection (Ch7) come from the ASP.NET Core shared framework (no package). Ch7 adds one line to the Fixed `Program.cs` (`AddDataProtection()`).
- **Known platform/runtime notes:** Ch10 SSRF uses a real loopback `HttpListener` (works cross-platform on .NET 8). Ch11 relies on `TypeNameHandling.All` (Newtonsoft) and a DTD-enabled `XmlReader`; the fixed XML path leans on the .NET 8 secure-by-default `DtdProcessing.Prohibit`.
- **Test-isolation patterns reused:** Ch9 and Ch13 use `WithWebHostBuilder` to inject configuration / a logging provider per test without modifying the shared factories.
- **Ch11 raw-body capture (Task 5):** both vulnerable and fixed JSON actions bind `[FromBody] JsonElement` and call `GetRawText()`, which reliably yields the original payload (including `$type`) regardless of model binding — avoiding the stream-already-consumed pitfall of reading `Request.Body` after binding.
```
