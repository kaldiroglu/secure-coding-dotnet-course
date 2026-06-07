using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class SsrfTests
{
    public record ImportResponse(string Fetched);

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Fact]
    public async Task Vulnerable_import_reaches_internal_service()
    {
        var port = FreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        var serve = Task.Run(async () =>
        {
            var ctx = await listener.GetContextAsync();
            var bytes = Encoding.UTF8.GetBytes("INTERNAL-SECRET-DATA");
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            ctx.Response.Close();
        });

        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsJsonAsync("/avatar/import", new { url = $"http://127.0.0.1:{port}/" });
        var body = await resp.Content.ReadFromJsonAsync<ImportResponse>();
        await serve;
        listener.Stop();

        Assert.Contains("INTERNAL-SECRET-DATA", body!.Fetched);
    }

    [Fact]
    public async Task Fixed_import_blocks_internal_targets()
    {
        var port = FreePort();
        using var f = new FixedFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsJsonAsync("/avatar/import", new { url = $"http://127.0.0.1:{port}/" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
