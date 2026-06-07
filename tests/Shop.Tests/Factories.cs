using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using VDb = dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using FDb = dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class VulnerableFactory : WebApplicationFactory<dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Program>
{
    private readonly SqliteConnection _conn = new("DataSource=:memory:");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        _conn.Open();
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<VDb.ShopDbContext>>();
            services.AddDbContext<VDb.ShopDbContext>(o => o.UseSqlite(_conn));
            using var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<VDb.ShopDbContext>();
            db.Database.EnsureCreated();
            VDb.SeedData.Populate(db);
        });
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _conn.Dispose();
        base.Dispose(disposing);
    }
}

public class FixedFactory : WebApplicationFactory<dev.kaldiroglu.SecureCoding.Shop.Fixed.Program>
{
    private readonly SqliteConnection _conn = new("DataSource=:memory:");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        _conn.Open();
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<FDb.ShopDbContext>>();
            services.AddDbContext<FDb.ShopDbContext>(o => o.UseSqlite(_conn));
            using var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<FDb.ShopDbContext>();
            db.Database.EnsureCreated();
            FDb.SeedData.Populate(db);
        });
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _conn.Dispose();
        base.Dispose(disposing);
    }
}
