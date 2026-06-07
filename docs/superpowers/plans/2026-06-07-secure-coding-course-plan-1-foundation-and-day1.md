# Secure Coding Course — Plan 1: Foundation + Day 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the runnable twin-project .NET 8 demo solution (Vulnerable + Fixed storefront Web APIs) and implement the six Day-1 secure-coding weakness chapters, each proven by an exploit test.

**Architecture:** Two ASP.NET Core 8 Web API projects with identical controllers — `Vulnerable` (seeded weaknesses) and `Fixed` (remediated) — over EF Core + SQLite. A single xUnit test project references both via `WebApplicationFactory` and, for each weakness, fires the exploit against Vulnerable (asserting it succeeds) and against Fixed (asserting it is blocked). Weaknesses are tagged in code with `// CWE-XXX` comments.

**Tech Stack:** .NET 8, C# 12, ASP.NET Core controllers, EF Core 8 + SQLite, xUnit, Microsoft.AspNetCore.Mvc.Testing.

**Companion spec:** `docs/superpowers/specs/2026-06-07-secure-coding-dotnet-course-design.md`

---

## File Structure

```
SecureCoding.NetBackend/
├─ SecureCoding.NetBackend.sln
├─ README.md
├─ Test.md
├─ src/
│  ├─ Vulnerable/Shop.Api/
│  │   ├─ Shop.Api.csproj                 # RootNamespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable
│  │   ├─ Program.cs
│  │   ├─ Domain/{Product,Review,User,Order}.cs
│  │   ├─ Data/ShopDbContext.cs
│  │   ├─ Data/SeedData.cs
│  │   └─ Controllers/{Products,Account,Invoices,Reports,Reviews,Orders}Controller.cs
│  └─ Fixed/Shop.Api/
│      └─ (mirror of Vulnerable, RootNamespace dev.kaldiroglu.SecureCoding.Shop.Fixed)
└─ tests/
   └─ Shop.Tests/
       ├─ Shop.Tests.csproj
       ├─ Factories.cs                     # typed WebApplicationFactory aliases
       └─ {Sqli,MassAssignment,PathTraversal,CommandInjection,OutputEncoding,AccessControl}Tests.cs
```

Each weakness lives in its own controller pair (Vulnerable vs Fixed) so a chapter is a self-contained diff. Files that change together (a controller and its test) are introduced in the same task.

---

## Task 1: Solution scaffold and Vulnerable project skeleton

**Files:**
- Create: `SecureCoding.NetBackend.sln`
- Create: `src/Vulnerable/Shop.Api/Shop.Api.csproj`
- Create: `src/Vulnerable/Shop.Api/Domain/Product.cs`, `Review.cs`, `User.cs`, `Order.cs`
- Create: `src/Vulnerable/Shop.Api/Data/ShopDbContext.cs`
- Create: `src/Vulnerable/Shop.Api/Data/SeedData.cs`
- Create: `src/Vulnerable/Shop.Api/Program.cs`

- [ ] **Step 1: Create the solution and project**

Run from the repo root:
```bash
mkdir -p src/Vulnerable src/Fixed tests
dotnet new sln -n SecureCoding.NetBackend
dotnet new webapi --use-controllers -o src/Vulnerable/Shop.Api -f net8.0
dotnet sln add src/Vulnerable/Shop.Api/Shop.Api.csproj
rm -f src/Vulnerable/Shop.Api/Controllers/WeatherForecastController.cs src/Vulnerable/Shop.Api/WeatherForecast.cs
```

- [ ] **Step 2: Set the csproj namespace and add EF Core SQLite**

Replace `src/Vulnerable/Shop.Api/Shop.Api.csproj` with:
```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <RootNamespace>dev.kaldiroglu.SecureCoding.Shop.Vulnerable</RootNamespace>
    <AssemblyName>dev.kaldiroglu.SecureCoding.Shop.Vulnerable</AssemblyName>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="8.0.6" />
  </ItemGroup>
</Project>
```

- [ ] **Step 3: Create the domain entities**

`src/Vulnerable/Shop.Api/Domain/Product.cs`:
```csharp
namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;

public class Product
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public decimal Price { get; set; }
}
```

`src/Vulnerable/Shop.Api/Domain/Review.cs`:
```csharp
namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;

public class Review
{
    public int Id { get; set; }
    public int ProductId { get; set; }
    public string Author { get; set; } = "";
    public string Body { get; set; } = "";
}
```

`src/Vulnerable/Shop.Api/Domain/User.cs`:
```csharp
namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;

public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool IsAdmin { get; set; }
}
```

`src/Vulnerable/Shop.Api/Domain/Order.cs`:
```csharp
namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;

public class Order
{
    public int Id { get; set; }
    public int OwnerId { get; set; }
    public string Item { get; set; } = "";
    public decimal Total { get; set; }
}
```

- [ ] **Step 4: Create the DbContext and seed**

`src/Vulnerable/Shop.Api/Data/ShopDbContext.cs`:
```csharp
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Microsoft.EntityFrameworkCore;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;

public class ShopDbContext(DbContextOptions<ShopDbContext> options) : DbContext(options)
{
    public DbSet<Product> Products => Set<Product>();
    public DbSet<Review> Reviews => Set<Review>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Order> Orders => Set<Order>();
}
```

`src/Vulnerable/Shop.Api/Data/SeedData.cs`:
```csharp
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
            new Order { OwnerId = 1, Item = "Laptop", Total = 1200m },   // Alice's order (id 1)
            new Order { OwnerId = 2, Item = "Mouse", Total = 25m });     // Bob's order   (id 2)

        db.Reviews.Add(new Review { ProductId = 1, Author = "alice", Body = "Great laptop" });
        db.SaveChanges();
    }
}
```

- [ ] **Step 5: Write Program.cs (with a test-friendly public Program)**

`src/Vulnerable/Shop.Api/Program.cs`:
```csharp
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDbContext<ShopDbContext>(o => o.UseSqlite("Data Source=shop-vulnerable.db"));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ShopDbContext>();
    db.Database.EnsureCreated();
    SeedData.Populate(db);
}

app.MapControllers();
app.Run();

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable
{
    public partial class Program { }   // exposed for WebApplicationFactory
}
```

- [ ] **Step 6: Verify it builds and runs**

Run:
```bash
dotnet build SecureCoding.NetBackend.sln
```
Expected: Build succeeded, 0 errors.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: scaffold solution and Vulnerable Shop.Api skeleton"
```

---

## Task 2: Mirror the Fixed project skeleton

**Files:**
- Create: `src/Fixed/Shop.Api/Shop.Api.csproj`
- Create: `src/Fixed/Shop.Api/Domain/{Product,Review,User,Order}.cs`
- Create: `src/Fixed/Shop.Api/Data/{ShopDbContext,SeedData}.cs`
- Create: `src/Fixed/Shop.Api/Program.cs`

- [ ] **Step 1: Create the Fixed project**

```bash
dotnet new webapi --use-controllers -o src/Fixed/Shop.Api -f net8.0
dotnet sln add src/Fixed/Shop.Api/Shop.Api.csproj
rm -f src/Fixed/Shop.Api/Controllers/WeatherForecastController.cs src/Fixed/Shop.Api/WeatherForecast.cs
```

- [ ] **Step 2: Set csproj namespace**

Replace `src/Fixed/Shop.Api/Shop.Api.csproj` with the Task 1 Step 2 content, but with both namespace values changed to `dev.kaldiroglu.SecureCoding.Shop.Fixed`.

- [ ] **Step 3: Copy the four domain entities, DbContext, and SeedData**

Create the same files as Task 1 Steps 3–4 under `src/Fixed/Shop.Api/`, replacing every occurrence of `...Shop.Vulnerable` with `...Shop.Fixed` in the `namespace` and `using` lines. The class bodies are identical.

- [ ] **Step 4: Write the Fixed Program.cs**

Identical to Task 1 Step 5 but with `Vulnerable` → `Fixed` in the namespaces and the SQLite file name `shop-fixed.db`:
```csharp
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
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
```

- [ ] **Step 5: Verify build**

Run: `dotnet build SecureCoding.NetBackend.sln`
Expected: Build succeeded, 0 errors.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: mirror Fixed Shop.Api skeleton"
```

---

## Task 3: Test project with isolated-DB factories

**Files:**
- Create: `tests/Shop.Tests/Shop.Tests.csproj`
- Create: `tests/Shop.Tests/Factories.cs`

- [ ] **Step 1: Create the test project and references**

```bash
dotnet new xunit -o tests/Shop.Tests -f net8.0
dotnet sln add tests/Shop.Tests/Shop.Tests.csproj
dotnet add tests/Shop.Tests/Shop.Tests.csproj package Microsoft.AspNetCore.Mvc.Testing --version 8.0.6
dotnet add tests/Shop.Tests/Shop.Tests.csproj package Microsoft.EntityFrameworkCore.Sqlite --version 8.0.6
dotnet add tests/Shop.Tests/Shop.Tests.csproj reference src/Vulnerable/Shop.Api/Shop.Api.csproj src/Fixed/Shop.Api/Shop.Api.csproj
```

- [ ] **Step 2: Add the FrameworkReference so WebApplicationFactory resolves**

Add inside the `<Project>` of `tests/Shop.Tests/Shop.Tests.csproj`:
```xml
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
```

- [ ] **Step 3: Write typed factories that swap each app to its own in-memory SQLite**

`tests/Shop.Tests/Factories.cs`:
```csharp
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
```

- [ ] **Step 4: Verify the test project builds**

Run: `dotnet build tests/Shop.Tests/Shop.Tests.csproj`
Expected: Build succeeded, 0 errors. (No tests yet.)

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test: add xUnit project with isolated in-memory SQLite factories"
```

---

## Task 4: Chapter 1 — CWE-89 SQL Injection (product search)

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/ProductsController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/ProductsController.cs`
- Create: `tests/Shop.Tests/SqliTests.cs`

- [ ] **Step 1: Write the failing tests**

`tests/Shop.Tests/SqliTests.cs`:
```csharp
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class SqliTests
{
    // Tautology injection that, if interpreted, returns ALL products regardless of the filter.
    // Must close the LIKE '%{q}%' template: the %' closes the pattern, OR 1=1 is always true,
    // and -- comments out the trailing %' the template appends.
    private const string Payload = "zzz%' OR 1=1 --";

    [Fact]
    public async Task Vulnerable_search_is_injectable()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var results = await client.GetFromJsonAsync<List<ProductDto>>($"/products/search?q={Uri.EscapeDataString(Payload)}");
        Assert.NotNull(results);
        Assert.True(results!.Count >= 2);   // injection leaked all rows
    }

    [Fact]
    public async Task Fixed_search_is_not_injectable()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var results = await client.GetFromJsonAsync<List<ProductDto>>($"/products/search?q={Uri.EscapeDataString(Payload)}");
        Assert.NotNull(results);
        Assert.Empty(results!);             // payload treated as a literal; matches nothing
    }

    public record ProductDto(int Id, string Name, string Description, decimal Price);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~SqliTests`
Expected: FAIL — controllers don't exist yet, requests 404 and deserialization throws.

- [ ] **Step 3: Implement the VULNERABLE controller**

`src/Vulnerable/Shop.Api/Controllers/ProductsController.cs`:
```csharp
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
```

- [ ] **Step 4: Implement the FIXED controller**

`src/Fixed/Shop.Api/Controllers/ProductsController.cs`:
```csharp
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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `dotnet test --filter FullyQualifiedName~SqliTests`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(ch1): CWE-89 SQL injection vulnerable/fixed product search + tests"
```

---

## Task 5: Chapter 2 — CWE-915/20 Mass assignment (user registration)

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/AccountController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/AccountController.cs`
- Create: `tests/Shop.Tests/MassAssignmentTests.cs`

- [ ] **Step 1: Write the failing tests**

`tests/Shop.Tests/MassAssignmentTests.cs`:
```csharp
using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class MassAssignmentTests
{
    // Attacker posts isAdmin:true hoping the binder sets it.
    private static readonly object Payload = new { email = "mallory@example.com", password = "pw", isAdmin = true };

    [Fact]
    public async Task Vulnerable_registration_allows_privilege_escalation()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/account/register", Payload);
        resp.EnsureSuccessStatusCode();
        var created = await resp.Content.ReadFromJsonAsync<UserView>();
        Assert.True(created!.IsAdmin);   // binder set IsAdmin from the body
    }

    [Fact]
    public async Task Fixed_registration_ignores_unexposed_fields()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/account/register", Payload);
        resp.EnsureSuccessStatusCode();
        var created = await resp.Content.ReadFromJsonAsync<UserView>();
        Assert.False(created!.IsAdmin);  // IsAdmin not bindable via the DTO
    }

    public record UserView(int Id, string Email, bool IsAdmin);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~MassAssignmentTests`
Expected: FAIL — `/account/register` returns 404.

- [ ] **Step 3: Implement the VULNERABLE controller**

`src/Vulnerable/Shop.Api/Controllers/AccountController.cs`:
```csharp
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("account")]
public class AccountController(ShopDbContext db) : ControllerBase
{
    // CWE-915: Mass assignment — model binder populates the EF entity directly,
    // so the client can set IsAdmin (CWE-20: untrusted input not constrained).
    [HttpPost("register")]
    public IActionResult Register([FromBody] User user)
    {
        user.Id = 0;
        db.Users.Add(user);
        db.SaveChanges();
        return Ok(new { user.Id, user.Email, user.IsAdmin });
    }
}
```

- [ ] **Step 4: Implement the FIXED controller**

`src/Fixed/Shop.Api/Controllers/AccountController.cs`:
```csharp
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Domain;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("account")]
public class AccountController(ShopDbContext db) : ControllerBase
{
    // FIXED: bind to a DTO exposing only what the client may set. IsAdmin is server-controlled.
    public record RegisterDto([Required, EmailAddress] string Email, [Required] string Password);

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterDto dto)
    {
        var user = new User { Email = dto.Email, PasswordHash = dto.Password, IsAdmin = false };
        db.Users.Add(user);
        db.SaveChanges();
        return Ok(new { user.Id, user.Email, user.IsAdmin });
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `dotnet test --filter FullyQualifiedName~MassAssignmentTests`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(ch2): CWE-915/20 mass assignment vulnerable/fixed registration + tests"
```

---

## Task 6: Chapter 3 — CWE-22 Path traversal (invoice download)

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/InvoicesController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/InvoicesController.cs`
- Create: `tests/Shop.Tests/PathTraversalTests.cs`

Both controllers serve files from a per-app `invoices/` folder created at startup. The Fixed version resolves the absolute path and verifies containment.

- [ ] **Step 1: Write the failing tests**

`tests/Shop.Tests/PathTraversalTests.cs`:
```csharp
using System.Net;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class PathTraversalTests
{
    // Climb out of the invoices folder to read a sibling secret file.
    private const string Payload = "../secret.txt";

    [Fact]
    public async Task Vulnerable_download_escapes_the_invoice_folder()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var resp = await client.GetAsync($"/invoices?name={Uri.EscapeDataString(Payload)}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("TOP-SECRET", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Fixed_download_blocks_traversal()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var resp = await client.GetAsync($"/invoices?name={Uri.EscapeDataString(Payload)}");
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~PathTraversalTests`
Expected: FAIL — `/invoices` returns 404.

- [ ] **Step 3: Implement the VULNERABLE controller**

`src/Vulnerable/Shop.Api/Controllers/InvoicesController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("invoices")]
public class InvoicesController : ControllerBase
{
    private static readonly string Root = InvoiceStore.EnsureSeeded();

    // CWE-22: Path traversal — user-supplied name joined to root without validation.
    [HttpGet]
    public IActionResult Download(string name)
    {
        var path = Path.Combine(Root, name);
        if (!System.IO.File.Exists(path)) return NotFound();
        return Content(System.IO.File.ReadAllText(path), "text/plain");
    }
}

public static class InvoiceStore
{
    public static string EnsureSeeded()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), "scc-vuln-files");
        var invoices = Path.Combine(baseDir, "invoices");
        Directory.CreateDirectory(invoices);
        System.IO.File.WriteAllText(Path.Combine(invoices, "inv-1001.txt"), "Invoice 1001: $1200");
        System.IO.File.WriteAllText(Path.Combine(baseDir, "secret.txt"), "TOP-SECRET admin key");
        return invoices;
    }
}
```

- [ ] **Step 4: Implement the FIXED controller**

`src/Fixed/Shop.Api/Controllers/InvoicesController.cs`:
```csharp
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("invoices")]
public class InvoicesController : ControllerBase
{
    private static readonly string Root = InvoiceStore.EnsureSeeded();

    // FIXED: resolve to an absolute path and require it to stay inside Root.
    [HttpGet]
    public IActionResult Download(string name)
    {
        var fullRoot = Path.GetFullPath(Root) + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(Path.Combine(Root, name));
        if (!candidate.StartsWith(fullRoot, StringComparison.Ordinal))
            return BadRequest("Invalid file name.");
        if (!System.IO.File.Exists(candidate)) return NotFound();
        return Content(System.IO.File.ReadAllText(candidate), "text/plain");
    }
}

public static class InvoiceStore
{
    public static string EnsureSeeded()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), "scc-fixed-files");
        var invoices = Path.Combine(baseDir, "invoices");
        Directory.CreateDirectory(invoices);
        System.IO.File.WriteAllText(Path.Combine(invoices, "inv-1001.txt"), "Invoice 1001: $1200");
        System.IO.File.WriteAllText(Path.Combine(baseDir, "secret.txt"), "TOP-SECRET admin key");
        return invoices;
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `dotnet test --filter FullyQualifiedName~PathTraversalTests`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(ch3): CWE-22 path traversal vulnerable/fixed invoice download + tests"
```

---

## Task 7: Chapter 4 — CWE-78 OS command injection (report export)

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/ReportsController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/ReportsController.cs`
- Create: `tests/Shop.Tests/CommandInjectionTests.cs`

> **Platform note:** the demo shells out to a POSIX shell (`/bin/sh`), matching the instructor's macOS/Linux environment. The vulnerable version builds a command line; the fixed version passes arguments and never invokes a shell. The exploit creates a sentinel file via `; touch …`.

- [ ] **Step 1: Write the failing tests**

`tests/Shop.Tests/CommandInjectionTests.cs`:
```csharp
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class CommandInjectionTests
{
    [Fact]
    public async Task Vulnerable_export_executes_injected_command()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-pwned-vuln.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = $"report; touch {sentinel}";

        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        await client.GetAsync($"/reports/export?title={Uri.EscapeDataString(payload)}");

        Assert.True(File.Exists(sentinel));   // injected command ran
        File.Delete(sentinel);
    }

    [Fact]
    public async Task Fixed_export_does_not_execute_injection()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-pwned-fixed.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = $"report; touch {sentinel}";

        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        await client.GetAsync($"/reports/export?title={Uri.EscapeDataString(payload)}");

        Assert.False(File.Exists(sentinel));  // treated as a literal argument
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~CommandInjectionTests`
Expected: FAIL — `/reports/export` returns 404 (sentinel never created for vulnerable test → its assertion fails).

- [ ] **Step 3: Implement the VULNERABLE controller**

`src/Vulnerable/Shop.Api/Controllers/ReportsController.cs`:
```csharp
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    // CWE-78: OS command injection — title concatenated into a shell command line.
    [HttpGet("export")]
    public IActionResult Export(string title)
    {
        var psi = new ProcessStartInfo("/bin/sh", $"-c \"echo {title}\"")
        {
            RedirectStandardOutput = true
        };
        using var proc = Process.Start(psi)!;
        proc.WaitForExit();
        return Ok(proc.StandardOutput.ReadToEnd());
    }
}
```

- [ ] **Step 4: Implement the FIXED controller**

`src/Fixed/Shop.Api/Controllers/ReportsController.cs`:
```csharp
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    // FIXED: no shell; the title is passed as a single argument via ArgumentList,
    // so shell metacharacters carry no meaning.
    [HttpGet("export")]
    public IActionResult Export(string title)
    {
        var psi = new ProcessStartInfo("/bin/echo") { RedirectStandardOutput = true };
        psi.ArgumentList.Add(title);
        using var proc = Process.Start(psi)!;
        proc.WaitForExit();
        return Ok(proc.StandardOutput.ReadToEnd());
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `dotnet test --filter FullyQualifiedName~CommandInjectionTests`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(ch4): CWE-78 command injection vulnerable/fixed report export + tests"
```

---

## Task 8: Chapter 5 — CWE-79 Output encoding (review widget)

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/ReviewsController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/ReviewsController.cs`
- Create: `tests/Shop.Tests/OutputEncodingTests.cs`

Both endpoints render a stored review into an HTML fragment (`text/html`). Vulnerable concatenates the body raw; Fixed HTML-encodes it.

- [ ] **Step 1: Write the failing tests**

`tests/Shop.Tests/OutputEncodingTests.cs`:
```csharp
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class OutputEncodingTests
{
    private const string Payload = "<script>alert(1)</script>";

    [Fact]
    public async Task Vulnerable_widget_reflects_raw_script()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/reviews", new { productId = 1, author = "x", body = Payload });
        var html = await client.GetStringAsync("/reviews/widget?productId=1");
        Assert.Contains("<script>alert(1)</script>", html);   // unencoded → executes in a browser
    }

    [Fact]
    public async Task Fixed_widget_encodes_output()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/reviews", new { productId = 1, author = "x", body = Payload });
        var html = await client.GetStringAsync("/reviews/widget?productId=1");
        Assert.DoesNotContain("<script>alert(1)</script>", html);
        Assert.Contains("&lt;script&gt;", html);              // encoded, inert
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~OutputEncodingTests`
Expected: FAIL — `/reviews` routes return 404.

- [ ] **Step 3: Implement the VULNERABLE controller**

`src/Vulnerable/Shop.Api/Controllers/ReviewsController.cs`:
```csharp
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
```

- [ ] **Step 4: Implement the FIXED controller**

`src/Fixed/Shop.Api/Controllers/ReviewsController.cs`:
```csharp
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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `dotnet test --filter FullyQualifiedName~OutputEncodingTests`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(ch5): CWE-79 output encoding vulnerable/fixed review widget + tests"
```

---

## Task 9: Chapter 6 — CWE-639/862/863 Broken access-control checks (orders)

**Files:**
- Create: `src/Vulnerable/Shop.Api/Controllers/OrdersController.cs`
- Create: `src/Fixed/Shop.Api/Controllers/OrdersController.cs`
- Create: `tests/Shop.Tests/AccessControlTests.cs`

The caller's authenticated identity is represented by an `X-User-Id` header (stand-in for a verified JWT subject). Seed data: order 1 belongs to user 1 (Alice), order 2 to user 2 (Bob). The Vulnerable endpoint returns any order by id; the Fixed endpoint requires the order to belong to the caller and returns 404 otherwise (not 403 — don't leak existence).

- [ ] **Step 1: Write the failing tests**

`tests/Shop.Tests/AccessControlTests.cs`:
```csharp
using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class AccessControlTests
{
    public record OrderView(int Id, int OwnerId, string Item, decimal Total);

    [Fact]
    public async Task Vulnerable_lets_bob_read_alices_order()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-User-Id", "2");          // Bob
        var order = await client.GetFromJsonAsync<OrderView>("/orders/1"); // Alice's order
        Assert.Equal(1, order!.OwnerId);                             // IDOR succeeded
    }

    [Fact]
    public async Task Fixed_blocks_bob_from_alices_order()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-User-Id", "2");          // Bob
        var resp = await client.GetAsync("/orders/1");               // Alice's order
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Fixed_allows_owner_to_read_own_order()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-User-Id", "2");          // Bob
        var order = await client.GetFromJsonAsync<OrderView>("/orders/2"); // Bob's order
        Assert.Equal(2, order!.OwnerId);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~AccessControlTests`
Expected: FAIL — `/orders/{id}` returns 404 for all (no controller).

- [ ] **Step 3: Implement the VULNERABLE controller**

`src/Vulnerable/Shop.Api/Controllers/OrdersController.cs`:
```csharp
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
```

- [ ] **Step 4: Implement the FIXED controller**

`src/Fixed/Shop.Api/Controllers/OrdersController.cs`:
```csharp
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using Microsoft.AspNetCore.Mvc;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("orders")]
public class OrdersController(ShopDbContext db) : ControllerBase
{
    // FIXED: scope the lookup to the authenticated caller; 404 (not 403) hides existence.
    [HttpGet("{id:int}")]
    public IActionResult Get(int id)
    {
        if (!int.TryParse(Request.Headers["X-User-Id"], out var userId))
            return Unauthorized();
        var order = db.Orders.FirstOrDefault(o => o.Id == id && o.OwnerId == userId);
        return order is null ? NotFound() : Ok(order);
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `dotnet test --filter FullyQualifiedName~AccessControlTests`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(ch6): CWE-639/862/863 access-control checks vulnerable/fixed orders + tests"
```

---

## Task 10: Root README.md and Test.md (per global conventions)

**Files:**
- Create: `README.md`
- Create: `Test.md`

- [ ] **Step 1: Write README.md**

`README.md`:
```markdown
# Secure Coding for .NET Backend Developers — Demo Solution

For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev

**Project:** Secure Coding for .NET Backend Developers (course demo codebase)
**Date:** 2026-06-07

## Purpose & expected benefits
A teaching codebase for a 2-day, demo-heavy secure-coding course. It pairs a
deliberately **Vulnerable** ASP.NET Core 8 Web API with a **Fixed** twin so an
instructor can live-demo each weakness and its remediation as a side-by-side diff.

## Functional properties
- Storefront backend: product search, registration, invoices, reports, reviews, orders.
- Day-1 weaknesses implemented: CWE-89 (SQL injection), CWE-915/20 (mass assignment),
  CWE-22 (path traversal), CWE-78 (command injection), CWE-79 (output encoding),
  CWE-639/862/863 (broken access-control checks).
- Each weakness is tagged in code with a `// CWE-XXX` comment.

## Architecture
- Two ASP.NET Core 8 Web API projects (`src/Vulnerable`, `src/Fixed`) with identical
  routes and distinct root namespaces (`dev.kaldiroglu.SecureCoding.Shop.Vulnerable`
  and `...Fixed`).
- EF Core 8 over SQLite; data seeded at startup.
- xUnit + `WebApplicationFactory` exploit tests prove each fix closes the hole.

## Run it with
```bash
# Build everything
dotnet build SecureCoding.NetBackend.sln

# Run the vulnerable API
dotnet run --project src/Vulnerable/Shop.Api

# Run the fixed API
dotnet run --project src/Fixed/Shop.Api

# Run all exploit tests
dotnet test
```
```

- [ ] **Step 2: Write Test.md**

`Test.md`:
```markdown
# Tests

For further enquiry please contact Akin Kaldiroglu at akin@kaldiroglu.dev

## Type of tests
**Integration / exploit tests.** Each test boots the real Web API in memory via
`WebApplicationFactory` and fires the actual attack over HTTP. For every weakness:
- the **Vulnerable** app is asserted to be exploitable (proving the demo is real), and
- the **Fixed** app is asserted to block the same attack (proving the remediation works).

Each app runs on its own isolated in-memory SQLite connection per test (see
`tests/Shop.Tests/Factories.cs`), so tests do not share state.

## Inventory (Day 1)
| Test class | Weakness | Asserts |
|------------|----------|---------|
| `SqliTests` | CWE-89 | tautology leaks all rows (vuln) / matches nothing (fixed) |
| `MassAssignmentTests` | CWE-915/20 | `isAdmin:true` honored (vuln) / ignored (fixed) |
| `PathTraversalTests` | CWE-22 | `../secret.txt` read (vuln) / 400 (fixed) |
| `CommandInjectionTests` | CWE-78 | `; touch` runs (vuln) / inert (fixed) — POSIX shell |
| `OutputEncodingTests` | CWE-79 | raw `<script>` reflected (vuln) / encoded (fixed) |
| `AccessControlTests` | CWE-639/862/863 | cross-user read (vuln) / 404 (fixed) |

## Run it with
```bash
dotnet test
# A single chapter, e.g.:
dotnet test --filter FullyQualifiedName~SqliTests
```
```

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: add root README.md and Test.md"
```

---

## Task 11: Full-suite verification

- [ ] **Step 1: Run the entire test suite**

Run: `dotnet test SecureCoding.NetBackend.sln`
Expected: PASS — 13 tests (2+2+2+2+2+3) across the six Day-1 chapters, 0 failures.

- [ ] **Step 2: Smoke-run both apps**

Run:
```bash
dotnet run --project src/Vulnerable/Shop.Api &
sleep 3
curl -s "http://localhost:5000/products/search?q=Laptop" || curl -s "http://localhost:5xxx/products/search?q=Laptop"
kill %1
```
Expected: a JSON array containing the Laptop product. (Note the actual port printed at startup; adjust the URL accordingly.)

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "test: verify full Day-1 suite green" --allow-empty
```

---

## Self-Review notes
- **Spec coverage (Day 1):** every Day-1 chapter in the spec (CWE-89, 915/20, 22, 78, 79, 639/862/863) has a dedicated task with vulnerable code, fixed code, and an exploit test. Orientation (Ch 0) and the coda are teaching segments with no code and are covered by Plan 3 (materials). Day-2 chapters and all course materials are intentionally deferred to Plans 2 and 3.
- **Namespace refinement:** spec §3 used `...Shop.Api` for both projects; this plan uses distinct `...Shop.Vulnerable` / `...Shop.Fixed` root namespaces (spec §7 open item resolved) so one test project can reference both without type collisions.
- **Platform caveat:** CWE-78 (Task 7) targets a POSIX shell; documented inline.
```
