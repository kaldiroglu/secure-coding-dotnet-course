using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Domain;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("account")]
public class AccountController(ShopDbContext db) : ControllerBase
{
    // FIXED: bind to a DTO exposing only what the client may set. IsAdmin is server-controlled.
    public record RegisterDto([Required, EmailAddress] string Email, [Required] string Password);

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterDto dto)
    {
        // NOTE: storing the raw password here keeps this chapter focused on mass assignment.
        // Proper password hashing (CWE-916) is the Day-2 crypto chapter.
        var user = new User { Email = dto.Email, PasswordHash = dto.Password, IsAdmin = false };
        db.Users.Add(user);
        db.SaveChanges();
        return Ok(new { user.Id, user.Email, user.IsAdmin });
    }
}
