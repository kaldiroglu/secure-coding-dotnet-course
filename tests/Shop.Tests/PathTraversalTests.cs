using System.Net;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class PathTraversalTests
{
    // Climb out of the invoices folder to read a sibling secret file.
    private const string Payload = "../secret.txt";

    [Fact]
    public async Task Vulnerable_download_escapes_the_invoice_folder()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var resp = await client.GetAsync($"/invoices?name={Uri.EscapeDataString(Payload)}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("TOP-SECRET", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Fixed_download_blocks_traversal()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var resp = await client.GetAsync($"/invoices?name={Uri.EscapeDataString(Payload)}");
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
