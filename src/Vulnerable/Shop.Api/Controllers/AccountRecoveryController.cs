using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("account")]
public class AccountRecoveryController : ControllerBase
{
    // CWE-330/338: System.Random seeded with a fixed/low-entropy value — output is fully predictable.
    [HttpGet("reset-token")]
    public IActionResult ResetToken()
    {
        var rng = new Random(20260607);
        var bytes = new byte[16];
        rng.NextBytes(bytes);
        return Ok(new { Token = Convert.ToHexString(bytes).ToLowerInvariant() });
    }
}
