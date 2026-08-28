public class Order
{
    public decimal Total { get; set; }
}

public static class TextExtensions
{
    public static string Shout(this string value)
    {
        return value.ToUpperInvariant();
    }

    public static decimal TotalWithTax(Order order)
    {
        return order.Total * 1.2m;
    }
}
