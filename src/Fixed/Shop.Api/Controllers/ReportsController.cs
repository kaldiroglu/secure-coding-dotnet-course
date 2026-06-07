using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    // FIXED: no shell; the title is passed as a single argument via ArgumentList,
    // so shell metacharacters carry no meaning.
    [HttpGet("export")]
    public IActionResult Export(string title)
    {
        var psi = new ProcessStartInfo("/bin/echo") { RedirectStandardOutput = true };
        psi.ArgumentList.Add(title);
        using var proc = Process.Start(psi)!;
        proc.WaitForExit();
        return Ok(proc.StandardOutput.ReadToEnd());
    }
}
