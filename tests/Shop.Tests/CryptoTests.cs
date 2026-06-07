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
        Assert.Equal(h1, h2);
        Assert.Equal(md5, h1);
    }

    [Fact]
    public async Task Fixed_password_hash_is_salted()
    {
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var h1 = (await (await c.PostAsJsonAsync("/crypto/hash", new { password = "hunter2" })).Content.ReadFromJsonAsync<HashResponse>())!.Hash;
        var h2 = (await (await c.PostAsJsonAsync("/crypto/hash", new { password = "hunter2" })).Content.ReadFromJsonAsync<HashResponse>())!.Hash;
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public async Task Vulnerable_ecb_leaks_identical_blocks()
    {
        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var ct = (await (await c.PostAsJsonAsync("/crypto/encrypt", new { plaintext = "YELLOW_SUBMARINEYELLOW_SUBMARINE" })).Content.ReadFromJsonAsync<CipherResponse>())!.Ciphertext;
        var bytes = Convert.FromBase64String(ct);
        Assert.Equal(bytes[..16], bytes[16..32]);
    }

    [Fact]
    public async Task Fixed_encryption_is_non_deterministic()
    {
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var ct1 = (await (await c.PostAsJsonAsync("/crypto/encrypt", new { plaintext = "YELLOW_SUBMARINEYELLOW_SUBMARINE" })).Content.ReadFromJsonAsync<CipherResponse>())!.Ciphertext;
        var ct2 = (await (await c.PostAsJsonAsync("/crypto/encrypt", new { plaintext = "YELLOW_SUBMARINEYELLOW_SUBMARINE" })).Content.ReadFromJsonAsync<CipherResponse>())!.Ciphertext;
        Assert.NotEqual(ct1, ct2);
    }
}
