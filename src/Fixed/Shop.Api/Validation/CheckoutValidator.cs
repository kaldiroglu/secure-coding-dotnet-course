using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using FluentValidation;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Validation;

// FIXED (CWE-20): FluentValidation expresses CROSS-FIELD and BUSINESS rules that
// DataAnnotations cannot — here a per-order total cap and a product-existence check.
public class CheckoutValidator : AbstractValidator<CheckoutDto>
{
    public const decimal PerOrderCap = 50_000m;

    public CheckoutValidator(ShopDbContext db)
    {
        RuleFor(x => x)
            .Must(dto => dto.UnitPrice * dto.Quantity <= PerOrderCap)
            .WithName("Total")
            .WithMessage($"Order total must not exceed {PerOrderCap}.");

        RuleFor(x => x.ProductId)
            .Must(id => db.Products.Any(p => p.Id == id))
            .WithMessage("Unknown product.");
    }
}
