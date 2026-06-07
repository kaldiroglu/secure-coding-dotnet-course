using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;

public static class SeedData
{
    public static void Populate(ShopDbContext db)
    {
        if (db.Products.Any()) return;

        db.Products.AddRange(
            new Product { Name = "Laptop", Description = "13-inch", Price = 1200m },
            new Product { Name = "Mouse", Description = "wireless", Price = 25m });

        db.Users.AddRange(
            new User { Email = "alice@example.com", PasswordHash = "seed", IsAdmin = false },
            new User { Email = "bob@example.com", PasswordHash = "seed", IsAdmin = false });

        db.Orders.AddRange(
            new Order { OwnerId = 1, Item = "Laptop", Total = 1200m },
            new Order { OwnerId = 2, Item = "Mouse", Total = 25m });

        db.Reviews.Add(new Review { ProductId = 1, Author = "alice", Body = "Great laptop" });
        db.SaveChanges();
    }
}
