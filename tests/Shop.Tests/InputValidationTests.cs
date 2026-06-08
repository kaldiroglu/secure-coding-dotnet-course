using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class InputValidationTests
{
    // Note is echoed in the response body so we can assert on validation/sanitization.
    public record OrderView(int Id, string Item, decimal Total, string? Note);

    private const string DirtyNote = "Ａ\r\n  hi  there  ";  // full-width A + CRLF + padding

    [Fact]
    public async Task Vulnerable_accepts_negative_quantity_producing_negative_total()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/checkout",
            new { productId = 1, quantity = -5, unitPrice = 0.01m, note = "x" });
        resp.EnsureSuccessStatusCode();
        var view = await resp.Content.ReadFromJsonAsync<OrderView>();
        Assert.True(view!.Total < 0);   // exploit: negative total accepted, no validation
    }

    [Fact]
    public async Task Vulnerable_stores_note_raw()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/checkout",
            new { productId = 1, quantity = 2, unitPrice = 10m, note = DirtyNote });
        resp.EnsureSuccessStatusCode();
        var view = await resp.Content.ReadFromJsonAsync<OrderView>();
        Assert.Equal(DirtyNote, view!.Note);   // raw: newline + full-width char survive untouched
    }
}
