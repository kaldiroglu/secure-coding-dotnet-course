using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    // CWE-78: OS command injection — title concatenated into a shell command line.
    [HttpGet("export")]
    public IActionResult Export(string title)
    {
        var psi = new ProcessStartInfo("/bin/sh", $"-c \"echo {title}\"")
        {
            RedirectStandardOutput = true
        };
        using var proc = Process.Start(psi)!;
        proc.WaitForExit();
        return Ok(proc.StandardOutput.ReadToEnd());
    }
}
