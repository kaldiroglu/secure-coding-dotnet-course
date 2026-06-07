using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("partner")]
public class PartnerController(IConfiguration config) : ControllerBase
{
    // FIXED: the secret comes from configuration (env var / user-secrets / vault), never from source.
    [HttpPost("webhook")]
    public IActionResult Webhook()
    {
        var expected = config["Partner:ApiKey"];
        var provided = Request.Headers["X-Api-Key"].ToString();
        if (string.IsNullOrEmpty(expected) || provided != expected) return Unauthorized();
        return Ok();
    }
}
