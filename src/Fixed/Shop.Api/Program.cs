using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDataProtection();
builder.Services.AddDbContext<ShopDbContext>(o => o.UseSqlite("Data Source=shop-fixed.db"));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ShopDbContext>();
    db.Database.EnsureCreated();
    SeedData.Populate(db);
}

app.MapControllers();
app.Run();

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed
{
    public partial class Program { }
}
