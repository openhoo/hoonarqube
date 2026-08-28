public class Order
{
    public decimal Total { get; set; }
}

public static class OrderExtensions
{
    public static decimal TotalWithTax(this Order order, decimal rate)
    {
        return order.Total + order.Total * rate;
    }
}
