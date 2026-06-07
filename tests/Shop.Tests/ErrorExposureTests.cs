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
        Assert.Contains("P@ssw0rd-SECRET", body);
        Assert.Contains("InvalidOperationException", body);
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
