using System.ComponentModel.DataAnnotations;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Validation;

// FIXED (CWE-20): DataAnnotations constrain field SHAPE. [ApiController] auto-returns
// 400 + ModelState BEFORE the action runs if any of these fail.
// Range(typeof(decimal), ...) is the precise form for money — avoids double rounding.
// ParseLimitsInInvariantCulture is REQUIRED: the limit strings ("0.01") would otherwise
// be parsed with the server's culture and throw on comma-decimal locales.
public record CheckoutDto(
    [Range(1, int.MaxValue)] int ProductId,
    [Range(1, 100)] int Quantity,
    [Range(typeof(decimal), "0.01", "100000", ParseLimitsInInvariantCulture = true)] decimal UnitPrice,
    [StringLength(200)] string? Note);
