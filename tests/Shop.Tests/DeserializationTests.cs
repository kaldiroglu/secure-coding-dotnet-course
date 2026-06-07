using System.Net;
using System.Net.Http;
using System.Text;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class DeserializationTests
{
    private static StringContent Json(string s) => new(s, Encoding.UTF8, "application/json");
    private static StringContent Xml(string s) => new(s, Encoding.UTF8, "application/xml");

    [Fact]
    public async Task Vulnerable_json_instantiates_attacker_type()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-deser-vuln.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = "{\"$type\":\"dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain.ImportGadget, dev.kaldiroglu.SecureCoding.Shop.Vulnerable\",\"Trigger\":\""
                      + sentinel.Replace("\\", "\\\\") + "\"}";

        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        await c.PostAsync("/import/json", Json(payload));

        Assert.True(File.Exists(sentinel));
        File.Delete(sentinel);
    }

    [Fact]
    public async Task Fixed_json_ignores_type_directives()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-deser-fixed.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = "{\"$type\":\"dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain.ImportGadget, dev.kaldiroglu.SecureCoding.Shop.Vulnerable\",\"Trigger\":\""
                      + sentinel.Replace("\\", "\\\\") + "\"}";

        using var f = new FixedFactory();
        var c = f.CreateClient();
        await c.PostAsync("/import/json", Json(payload));

        Assert.False(File.Exists(sentinel));
    }

    [Fact]
    public async Task Vulnerable_xml_expands_external_entity()
    {
        var secret = Path.Combine(Path.GetTempPath(), "scc-xxe-secret.txt");
        File.WriteAllText(secret, "XXE-SECRET-9999");
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://" + secret + "\">]><foo>&xxe;</foo>";

        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var body = await (await c.PostAsync("/import/xml", Xml(xml))).Content.ReadAsStringAsync();

        Assert.Contains("XXE-SECRET-9999", body);
    }

    [Fact]
    public async Task Fixed_xml_rejects_dtd()
    {
        var secret = Path.Combine(Path.GetTempPath(), "scc-xxe-secret.txt");
        File.WriteAllText(secret, "XXE-SECRET-9999");
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://" + secret + "\">]><foo>&xxe;</foo>";

        using var f = new FixedFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsync("/import/xml", Xml(xml));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
