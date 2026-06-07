using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("session")]
public class SessionController(ILogger<SessionController> logger) : ControllerBase
{
    public record LoginRequest(string Username, string Password);

    // FIXED: log only non-sensitive context (never the password/token), and neutralize
    // CR/LF in the untrusted username so it can't forge log entries (CWE-117, see Chapter 14).
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        var safeUser = req.Username.Replace("\r", "").Replace("\n", "");
        logger.LogInformation("Login attempt for user {User}", safeUser);
        return Ok();
    }
}
