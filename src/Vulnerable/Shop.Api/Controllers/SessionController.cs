using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("session")]
public class SessionController(ILogger<SessionController> logger) : ControllerBase
{
    public record LoginRequest(string Username, string Password);

    // CWE-532: logs the credential. Anyone with log access now has the password.
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        logger.LogInformation("Login attempt: user={User} password={Password}", req.Username, req.Password);
        return Ok();
    }
}
