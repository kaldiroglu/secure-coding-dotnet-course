using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("crypto")]
public class CryptoController(IDataProtectionProvider dp) : ControllerBase
{
    public record HashRequest(string Password);
    public record EncryptRequest(string Plaintext);

    private static readonly PasswordHasher<object> Hasher = new();
    private static readonly object Dummy = new();

    // FIXED: PBKDF2 via ASP.NET Core Identity's PasswordHasher — per-hash random salt + work factor.
    [HttpPost("hash")]
    public IActionResult Hash([FromBody] HashRequest req) =>
        Ok(new { Hash = Hasher.HashPassword(Dummy, req.Password) });

    // FIXED: never hand-roll crypto — use the Data Protection API (authenticated, random subkeys).
    [HttpPost("encrypt")]
    public IActionResult Encrypt([FromBody] EncryptRequest req)
    {
        var protector = dp.CreateProtector("shop.crypto.demo");
        return Ok(new { Ciphertext = protector.Protect(req.Plaintext) });
    }
}
