using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("account")]
public class AccountRecoveryController : ControllerBase
{
    // FIXED: security tokens come from a CSPRNG.
    [HttpGet("reset-token")]
    public IActionResult ResetToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Ok(new { Token = Convert.ToHexString(bytes).ToLowerInvariant() });
    }
}
