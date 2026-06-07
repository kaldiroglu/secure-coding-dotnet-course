using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("session")]
public class SessionController(ILogger<SessionController> logger) : ControllerBase
{
    public record LoginRequest(string Username, string Password);

    // FIXED: log only non-sensitive context; never the password/token.
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        logger.LogInformation("Login attempt for user {User}", req.Username);
        return Ok();
    }
}
