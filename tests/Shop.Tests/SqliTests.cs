using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class SqliTests
{
    // Tautology injection that, if interpreted, returns ALL products regardless of the filter.
    // The vulnerable controller builds: SELECT * FROM Products WHERE Name LIKE '%{q}%'
    // With this payload that becomes: ...LIKE '%zzz%' OR 1=1 --'%'
    // The OR 1=1 makes it return every row; -- comments out the trailing fragment.
    private const string Payload = "zzz%' OR 1=1 --";

    [Fact]
    public async Task Vulnerable_search_is_injectable()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var results = await client.GetFromJsonAsync<List<ProductDto>>($"/products/search?q={Uri.EscapeDataString(Payload)}");
        Assert.NotNull(results);
        Assert.True(results!.Count >= 2);   // injection leaked all rows
    }

    [Fact]
    public async Task Fixed_search_is_not_injectable()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var results = await client.GetFromJsonAsync<List<ProductDto>>($"/products/search?q={Uri.EscapeDataString(Payload)}");
        Assert.NotNull(results);
        Assert.Empty(results!);             // payload treated as a literal; matches nothing
    }

    public record ProductDto(int Id, string Name, string Description, decimal Price);
}
