using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("avatar")]
public class AvatarController : ControllerBase
{
    public record ImportRequest(string Url);

    // FIXED: validate the destination against an allow-list; never let input pick where the server connects.
    [HttpPost("import")]
    public async Task<IActionResult> Import([FromBody] ImportRequest req)
    {
        if (!Uri.TryCreate(req.Url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return BadRequest("Invalid URL.");
        if (uri.IsLoopback || !uri.Host.EndsWith(".example.com", StringComparison.OrdinalIgnoreCase))
            return BadRequest("Destination not allowed.");

        using var http = new HttpClient();
        var content = await http.GetStringAsync(uri);
        return Ok(new { Fetched = content });
    }
}
