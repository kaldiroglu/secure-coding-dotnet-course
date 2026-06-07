using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("avatar")]
public class AvatarController : ControllerBase
{
    public record ImportRequest(string Url);

    // CWE-918: SSRF — the server fetches whatever URL the client supplies, including internal hosts.
    [HttpPost("import")]
    public async Task<IActionResult> Import([FromBody] ImportRequest req)
    {
        using var http = new HttpClient();
        var content = await http.GetStringAsync(req.Url);
        return Ok(new { Fetched = content });
    }
}
