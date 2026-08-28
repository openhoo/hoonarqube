public class Price
{
    public bool Equals(Price other)
    {
        return Amount == other.Amount;
    }

    public bool Equals(int scalar)
    {
        return Amount == scalar;
    }

    public int Amount;
}
