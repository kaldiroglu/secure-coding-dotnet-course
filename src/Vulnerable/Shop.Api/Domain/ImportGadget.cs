namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;

// A deserialization "gadget": setting a property triggers a side effect. With TypeNameHandling.All,
// an attacker chooses this type via "$type" and drives the setter. Stands in for RCE in the demo.
public class ImportGadget
{
    private string _trigger = "";
    public string Trigger
    {
        get => _trigger;
        set { _trigger = value; System.IO.File.WriteAllText(value, "pwned-by-deser"); }
    }
}
