using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class CommandInjectionTests
{
    [Fact]
    public async Task Vulnerable_export_executes_injected_command()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-pwned-vuln.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = $"report; touch {sentinel}";

        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        await client.GetAsync($"/reports/export?title={Uri.EscapeDataString(payload)}");

        Assert.True(File.Exists(sentinel));   // injected command ran
        File.Delete(sentinel);
    }

    [Fact]
    public async Task Fixed_export_does_not_execute_injection()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-pwned-fixed.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = $"report; touch {sentinel}";

        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        await client.GetAsync($"/reports/export?title={Uri.EscapeDataString(payload)}");

        Assert.False(File.Exists(sentinel));  // treated as a literal argument
    }
}
