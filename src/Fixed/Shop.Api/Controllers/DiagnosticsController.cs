using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("diagnostics")]
public class DiagnosticsController(ILogger<DiagnosticsController> logger) : ControllerBase
{
    // FIXED: log details server-side; return a generic ProblemDetails to the caller.
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
            logger.LogError(ex, "Diagnostics run failed");
            return StatusCode(500, new ProblemDetails
            {
                Title = "An unexpected error occurred.",
                Status = 500
            });
        }
    }
}
