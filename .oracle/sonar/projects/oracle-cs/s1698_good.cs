class Money
{
    private readonly int amount;
}

class Wallet
{
    public bool Same(Money left, Money right)
    {
        return left == right;
    }
}
