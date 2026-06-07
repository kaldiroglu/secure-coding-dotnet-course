using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("orders")]
public class OrdersController(ShopDbContext db) : ControllerBase
{
    // FIXED (CWE-639/862/863): scope the lookup to the authenticated caller; 404 (not 403) hides existence.
    // NOTE: X-User-Id stands in for a verified identity (e.g. a JWT subject). Never trust a
    // raw client header for identity in real code — that is an auth-design concern, out of scope here.
    [HttpGet("{id:int}")]
    public IActionResult Get(int id)
    {
        if (!int.TryParse(Request.Headers["X-User-Id"].ToString(), out var userId))
            return Unauthorized();
        var order = db.Orders.FirstOrDefault(o => o.Id == id && o.OwnerId == userId);
        return order is null ? NotFound() : Ok(order);
    }
}
