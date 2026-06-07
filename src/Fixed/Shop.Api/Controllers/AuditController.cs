using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("audit")]
public class AuditController(ILogger<AuditController> logger) : ControllerBase
{
    public record AuditRequest(string Action);

    // FIXED: neutralize CR/LF in untrusted data before it enters the log, so it cannot
    // forge new log lines. The content is preserved, just collapsed onto a single line.
    [HttpPost]
    public IActionResult Record([FromBody] AuditRequest req)
    {
        var safe = req.Action.Replace("\r", "").Replace("\n", "");
        logger.LogInformation("Audit: user action = {Action}", safe);
        return Ok();
    }
}
