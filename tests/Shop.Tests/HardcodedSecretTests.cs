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
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
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
