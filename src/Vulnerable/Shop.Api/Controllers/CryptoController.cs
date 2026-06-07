using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("crypto")]
public class CryptoController : ControllerBase
{
    public record HashRequest(string Password);
    public record EncryptRequest(string Plaintext);

    // CWE-916: unsalted, fast hash — trivially cracked / rainbow-tabled.
    [HttpPost("hash")]
    public IActionResult Hash([FromBody] HashRequest req)
    {
        var hex = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(req.Password))).ToLowerInvariant();
        return Ok(new { Hash = hex });
    }

    // CWE-327: AES in ECB mode — identical plaintext blocks produce identical ciphertext blocks.
    [HttpPost("encrypt")]
    public IActionResult Encrypt([FromBody] EncryptRequest req)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes("0123456789ABCDEF"); // hardcoded 128-bit key (also bad)
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        var data = Encoding.UTF8.GetBytes(req.Plaintext);
        var ct = aes.EncryptEcb(data, PaddingMode.PKCS7);
        return Ok(new { Ciphertext = Convert.ToBase64String(ct) });
    }
}
