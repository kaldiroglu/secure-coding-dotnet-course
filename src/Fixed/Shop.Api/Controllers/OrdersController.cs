using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("orders")]
public class OrdersController(ShopDbContext db) : ControllerBase
{
    // FIXED: scope the lookup to the authenticated caller; 404 (not 403) hides existence.
    [HttpGet("{id:int}")]
    public IActionResult Get(int id)
    {
        if (!int.TryParse(Request.Headers["X-User-Id"].ToString(), out var userId))
            return Unauthorized();
        var order = db.Orders.FirstOrDefault(o => o.Id == id && o.OwnerId == userId);
        return order is null ? NotFound() : Ok(order);
    }
}
