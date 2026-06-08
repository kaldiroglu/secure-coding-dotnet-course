using System.ComponentModel.DataAnnotations;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Validation;

// FIXED (CWE-20): DataAnnotations constrain field SHAPE. [ApiController] auto-returns
// 400 + ModelState BEFORE the action runs if any of these fail.
// Range(typeof(decimal), ...) is the precise form for money — avoids double rounding.
public record CheckoutDto(
    [property: Range(1, int.MaxValue)] int ProductId,
    [property: Range(1, 100)] int Quantity,
    [property: Range(typeof(decimal), "0.01", "100000")] decimal UnitPrice,
    [property: StringLength(200)] string? Note);
