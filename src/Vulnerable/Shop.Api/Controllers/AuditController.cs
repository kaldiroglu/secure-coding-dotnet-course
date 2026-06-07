using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("audit")]
public class AuditController(ILogger<AuditController> logger) : ControllerBase
{
    public record AuditRequest(string Action);

    // CWE-117: untrusted input written to the log without neutralizing newlines, so an
    // attacker can inject CR/LF and forge additional, fake log entries (log injection).
    [HttpPost]
    public IActionResult Record([FromBody] AuditRequest req)
    {
        logger.LogInformation("Audit: user action = {Action}", req.Action);
        return Ok();
    }
}
