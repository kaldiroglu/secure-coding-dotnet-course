using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class MassAssignmentTests
{
    // Attacker posts isAdmin:true hoping the binder sets it.
    private static readonly object Payload = new { email = "mallory@example.com", password = "pw", isAdmin = true };

    [Fact]
    public async Task Vulnerable_registration_allows_privilege_escalation()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/account/register", Payload);
        resp.EnsureSuccessStatusCode();
        var created = await resp.Content.ReadFromJsonAsync<UserView>();
        Assert.True(created!.IsAdmin);   // binder set IsAdmin from the body
    }

    [Fact]
    public async Task Fixed_registration_ignores_unexposed_fields()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/account/register", Payload);
        resp.EnsureSuccessStatusCode();
        var created = await resp.Content.ReadFromJsonAsync<UserView>();
        Assert.False(created!.IsAdmin);  // IsAdmin not bindable via the DTO
    }

    public record UserView(int Id, string Email, bool IsAdmin);
}
