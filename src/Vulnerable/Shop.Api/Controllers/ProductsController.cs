using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("products")]
public class ProductsController(ShopDbContext db) : ControllerBase
{
    // CWE-89: SQL Injection — user input concatenated into a raw SQL string.
    [HttpGet("search")]
    public async Task<List<Product>> Search(string q)
    {
        var sql = $"SELECT * FROM Products WHERE Name LIKE '%{q}%'";
        return await db.Products.FromSqlRaw(sql).ToListAsync();
    }
}
