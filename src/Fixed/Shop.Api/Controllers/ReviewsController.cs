using System.Text;
using System.Text.Encodings.Web;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Domain;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

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

    // FIXED: HTML-encode untrusted content for the HTML context before output.
    [HttpGet("widget")]
    public IActionResult Widget(int productId)
    {
        var sb = new StringBuilder("<ul>");
        foreach (var r in db.Reviews.Where(r => r.ProductId == productId))
            sb.Append($"<li>{HtmlEncoder.Default.Encode(r.Body)}</li>");
        sb.Append("</ul>");
        return Content(sb.ToString(), "text/html");
    }
}
