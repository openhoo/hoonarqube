class Money
{
    public override bool Equals(object other)
    {
        return true;
    }
}

class Wallet
{
    public bool Same(Money left, Money right)
    {
        return left == right;
    }
}
