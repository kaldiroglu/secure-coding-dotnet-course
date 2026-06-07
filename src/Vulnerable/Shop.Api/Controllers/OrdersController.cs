using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("orders")]
public class OrdersController(ShopDbContext db) : ControllerBase
{
    // CWE-639/862: object returned by id with no ownership/authorization check.
    [HttpGet("{id:int}")]
    public IActionResult Get(int id)
    {
        var order = db.Orders.Find(id);
        return order is null ? NotFound() : Ok(order);
    }
}
