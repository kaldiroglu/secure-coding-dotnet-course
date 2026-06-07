using System.Text;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("reviews")]
public class ReviewsController(ShopDbContext db) : ControllerBase
{
    public record ReviewDto(int ProductId, string Author, string Body);

    [HttpPost]
    public IActionResult Add([FromBody] ReviewDto dto)
    {
        db.Reviews.Add(new Review { ProductId = dto.ProductId, Author = dto.Author, Body = dto.Body });
        db.SaveChanges();
        return Ok();
    }

    // CWE-79: review body written into HTML without encoding (stored XSS).
    [HttpGet("widget")]
    public IActionResult Widget(int productId)
    {
        var sb = new StringBuilder("<ul>");
        foreach (var r in db.Reviews.Where(r => r.ProductId == productId))
            sb.Append($"<li>{r.Body}</li>");
        sb.Append("</ul>");
        return Content(sb.ToString(), "text/html");
    }
}
