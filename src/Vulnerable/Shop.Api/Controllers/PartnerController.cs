using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("partner")]
public class PartnerController : ControllerBase
{
    // CWE-798: secret hardcoded in source — present in the compiled binary, discoverable by anyone.
    private const string ApiKey = "sk_live_51HARDCODEDpartnerKEY";

    [HttpPost("webhook")]
    public IActionResult Webhook()
    {
        var provided = Request.Headers["X-Api-Key"].ToString();
        return provided == ApiKey ? Ok() : Unauthorized();
    }
}
