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

        var rng = new Random(Seed);
        var bytes = new byte[16];
        rng.NextBytes(bytes);
        var predicted = Convert.ToHexString(bytes).ToLowerInvariant();

        Assert.Equal(t1, t2);
        Assert.Equal(predicted, t1);
    }

    [Fact]
    public async Task Fixed_tokens_are_unpredictable_and_unique()
    {
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var t1 = (await c.GetFromJsonAsync<TokenResponse>("/account/reset-token"))!.Token;
        var t2 = (await c.GetFromJsonAsync<TokenResponse>("/account/reset-token"))!.Token;
        Assert.NotEqual(t1, t2);
        Assert.True(Convert.FromHexString(t1).Length >= 32);
    }
}
