using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("invoices")]
public class InvoicesController : ControllerBase
{
    private static readonly string Root = InvoiceStore.EnsureSeeded();

    // CWE-22: Path traversal — user-supplied name joined to root without validation.
    [HttpGet]
    public IActionResult Download(string name)
    {
        var path = Path.Combine(Root, name);
        if (!System.IO.File.Exists(path)) return NotFound();
        return Content(System.IO.File.ReadAllText(path), "text/plain");
    }
}

public static class InvoiceStore
{
    public static string EnsureSeeded()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), "scc-vuln-files");
        var invoices = Path.Combine(baseDir, "invoices");
        Directory.CreateDirectory(invoices);
        System.IO.File.WriteAllText(Path.Combine(invoices, "inv-1001.txt"), "Invoice 1001: $1200");
        System.IO.File.WriteAllText(Path.Combine(baseDir, "secret.txt"), "TOP-SECRET admin key");
        return invoices;
    }
}
