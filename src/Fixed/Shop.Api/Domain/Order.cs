namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Domain;

public class Order
{
    public int Id { get; set; }
    public int OwnerId { get; set; }
    public string Item { get; set; } = "";
    public decimal Total { get; set; }
}
