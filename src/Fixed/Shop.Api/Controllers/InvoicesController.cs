using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("invoices")]
public class InvoicesController : ControllerBase
{
    private static readonly string Root = InvoiceStore.EnsureSeeded();

    // FIXED: resolve to an absolute path and require it to stay inside Root.
    [HttpGet]
    public IActionResult Download(string name)
    {
        var fullRoot = Path.GetFullPath(Root) + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(Path.Combine(Root, name));
        if (!candidate.StartsWith(fullRoot, StringComparison.Ordinal))
            return BadRequest("Invalid file name.");
        // Justified suppression (teaching point): the path is sanitized above by the
        // canonicalize-then-containment check, but the taint analyzers (CA3003 / SCS0018)
        // don't recognize that guard as a sanitizer, so they still flag these file ops.
        // Suppress narrowly here — with this justification — never disable the rule solution-wide.
#pragma warning disable CA3003, SCS0018 // Path is contained within Root by the check above.
        if (!System.IO.File.Exists(candidate)) return NotFound();
        return Content(System.IO.File.ReadAllText(candidate), "text/plain");
#pragma warning restore CA3003, SCS0018
    }
}

public static class InvoiceStore
{
    public static string EnsureSeeded()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), "scc-fixed-files");
        var invoices = Path.Combine(baseDir, "invoices");
        Directory.CreateDirectory(invoices);
        System.IO.File.WriteAllText(Path.Combine(invoices, "inv-1001.txt"), "Invoice 1001: $1200");
        System.IO.File.WriteAllText(Path.Combine(baseDir, "secret.txt"), "TOP-SECRET admin key");
        return invoices;
    }
}
