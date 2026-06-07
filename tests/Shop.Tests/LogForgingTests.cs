using System.Linq;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class LogForgingTests
{
    // A newline-injected value that forges a second, fake log line.
    private const string Payload = "view\n2026-06-08 00:00:00 [WARN] user 'admin' deleted all records";

    [Fact]
    public async Task Vulnerable_log_can_be_forged()
    {
        var sink = new ListLoggerProvider();
        using var f = new VulnerableFactory();
        using var configured = f.WithWebHostBuilder(b =>
            b.ConfigureLogging(lb => { lb.ClearProviders(); lb.AddProvider(sink); lb.SetMinimumLevel(LogLevel.Information); }));
        var c = configured.CreateClient();

        await c.PostAsJsonAsync("/audit", new { action = Payload });

        // The forged content reaches the log on its own line — log injection succeeded.
        Assert.Contains(sink.Messages, m => m.Contains("Audit:") && m.Contains('\n') && m.Contains("deleted all records"));
    }

    [Fact]
    public async Task Fixed_log_is_neutralized()
    {
        var sink = new ListLoggerProvider();
        using var f = new FixedFactory();
        using var configured = f.WithWebHostBuilder(b =>
            b.ConfigureLogging(lb => { lb.ClearProviders(); lb.AddProvider(sink); lb.SetMinimumLevel(LogLevel.Information); }));
        var c = configured.CreateClient();

        await c.PostAsJsonAsync("/audit", new { action = Payload });

        var audit = sink.Messages.Where(m => m.Contains("Audit:")).ToList();
        Assert.NotEmpty(audit);
        Assert.DoesNotContain(audit, m => m.Contains('\n'));          // newlines neutralized
        Assert.Contains(audit, m => m.Contains("deleted all records")); // content kept, on one line
    }
}
