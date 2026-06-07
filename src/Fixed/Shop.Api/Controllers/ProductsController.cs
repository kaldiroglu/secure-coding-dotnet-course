using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Domain;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("products")]
public class ProductsController(ShopDbContext db) : ControllerBase
{
    // FIXED: LINQ parameterizes the value; input can never alter the query structure.
    [HttpGet("search")]
    public async Task<List<Product>> Search(string q) =>
        await db.Products.Where(p => p.Name.Contains(q)).ToListAsync();
}
