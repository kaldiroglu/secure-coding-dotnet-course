using dev.kaldiroglu.SecureCoding.Shop.Fixed.Domain;
using Microsoft.EntityFrameworkCore;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;

public class ShopDbContext(DbContextOptions<ShopDbContext> options) : DbContext(options)
{
    public DbSet<Product> Products => Set<Product>();
    public DbSet<Review> Reviews => Set<Review>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Order> Orders => Set<Order>();
}
