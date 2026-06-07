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

        Assert.Contains(sink.Messages, m => m.Contains(Password));
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
        Assert.Contains(sink.Messages, m => m.Contains("alice"));
    }
}
