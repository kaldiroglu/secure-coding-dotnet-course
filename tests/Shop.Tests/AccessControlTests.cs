using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class AccessControlTests
{
    public record OrderView(int Id, int OwnerId, string Item, decimal Total);

    [Fact]
    public async Task Vulnerable_lets_bob_read_alices_order()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-User-Id", "2");          // Bob
        var order = await client.GetFromJsonAsync<OrderView>("/orders/1"); // Alice's order
        Assert.Equal(1, order!.OwnerId);                             // IDOR succeeded
    }

    [Fact]
    public async Task Fixed_blocks_bob_from_alices_order()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-User-Id", "2");          // Bob
        var resp = await client.GetAsync("/orders/1");               // Alice's order
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Fixed_allows_owner_to_read_own_order()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-User-Id", "2");          // Bob
        var order = await client.GetFromJsonAsync<OrderView>("/orders/2"); // Bob's order
        Assert.Equal(2, order!.OwnerId);
    }
}
