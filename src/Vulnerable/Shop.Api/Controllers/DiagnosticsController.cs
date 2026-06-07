using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("diagnostics")]
public class DiagnosticsController : ControllerBase
{
    // CWE-209: returns the full exception (stack trace + sensitive message) to the caller.
    [HttpGet("run")]
    public IActionResult Run()
    {
        try
        {
            throw new InvalidOperationException(
                "DB connection failed: Server=db;User=sa;Password=P@ssw0rd-SECRET");
        }
        catch (Exception ex)
        {
            return StatusCode(500, ex.ToString());
        }
    }
}
