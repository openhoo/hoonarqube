public class Account
{
    public string Name { get; set; }

    public decimal Balance { get; set; }

    public string GetName()
    {
        return Name;
    }

    public decimal GetBalance()
    {
        return Balance;
    }
}
