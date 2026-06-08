using dev.kaldiroglu.SecureCoding.Shop.Fixed.Data;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Domain;
using dev.kaldiroglu.SecureCoding.Shop.Fixed.Validation;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.RegularExpressions;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("checkout")]
public class CheckoutController(ShopDbContext db, IValidator<CheckoutDto> validator) : ControllerBase
{
    [HttpPost]
    public IActionResult Place([FromBody] CheckoutDto dto)
    {
        // FIXED (CWE-20): [ApiController] has already enforced the DataAnnotations field
        // shape (it returns 400 + ModelState before we get here). Now apply the cross-field
        // / business rules that DataAnnotations cannot express.
        var result = validator.Validate(dto);
        if (!result.IsValid)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError(error.PropertyName, error.ErrorMessage);
            return ValidationProblem(ModelState);
        }

        // FIXED (CWE-20): free-form text is normalized then sanitized, in that order,
        // BEFORE it is trusted. Normalizing after validating would allow a canonicalization
        // bypass (a visually-equivalent string passes the check, then folds into the dangerous form).
        var note = Sanitize(dto.Note);

        var product = db.Products.Find(dto.ProductId)!;   // existence guaranteed by the validator
        var total = dto.UnitPrice * dto.Quantity;
        var order = new Order { OwnerId = 0, Item = product.Name, Total = total };
        db.Orders.Add(order);
        db.SaveChanges();
        return Ok(new { order.Id, order.Item, order.Total, Note = note });
    }

    // Normalize (NFKC) -> strip control chars -> collapse whitespace & trim.
    private static string Sanitize(string? input)
    {
        if (string.IsNullOrEmpty(input)) return "";
        var normalized = input.Normalize(NormalizationForm.FormKC);
        var noControl = new string(normalized.Where(c => !char.IsControl(c)).ToArray());
        return Regex.Replace(noControl, @"\s+", " ").Trim();
    }
}
