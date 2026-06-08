using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("checkout")]
public class CheckoutController(ShopDbContext db) : ControllerBase
{
    public record CheckoutDto(int ProductId, int Quantity, decimal UnitPrice, string? Note);

    // CWE-20: no validation of any kind. Negative/absurd quantity & price flow straight
    // into the total; the free-form note is echoed back raw (newlines, control chars and all).
    [HttpPost]
    public IActionResult Place([FromBody] CheckoutDto dto)
    {
        var item = db.Products.Find(dto.ProductId)?.Name ?? "unknown";
        var total = dto.UnitPrice * dto.Quantity;
        var order = new Order { OwnerId = 0, Item = item, Total = total };
        db.Orders.Add(order);
        db.SaveChanges();
        return Ok(new { order.Id, order.Item, order.Total, dto.Note });
    }
}
