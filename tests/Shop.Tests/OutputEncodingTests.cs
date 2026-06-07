using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class OutputEncodingTests
{
    private const string Payload = "<script>alert(1)</script>";

    [Fact]
    public async Task Vulnerable_widget_reflects_raw_script()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/reviews", new { productId = 1, author = "x", body = Payload });
        var html = await client.GetStringAsync("/reviews/widget?productId=1");
        Assert.Contains("<script>alert(1)</script>", html);   // unencoded -> executes in a browser
    }

    [Fact]
    public async Task Fixed_widget_encodes_output()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/reviews", new { productId = 1, author = "x", body = Payload });
        var html = await client.GetStringAsync("/reviews/widget?productId=1");
        Assert.DoesNotContain("<script>alert(1)</script>", html);
        Assert.Contains("&lt;script&gt;", html);              // encoded, inert
    }
}
