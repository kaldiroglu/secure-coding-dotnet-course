using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("account")]
public class AccountController(ShopDbContext db) : ControllerBase
{
    // CWE-915: Mass assignment — model binder populates the EF entity directly,
    // so the client can set IsAdmin (CWE-20: untrusted input not constrained).
    [HttpPost("register")]
    public IActionResult Register([FromBody] User user)
    {
        user.Id = 0;
        db.Users.Add(user);
        db.SaveChanges();
        return Ok(new { user.Id, user.Email, user.IsAdmin });
    }
}
