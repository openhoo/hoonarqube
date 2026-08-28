public class Account
{
    public override bool Equals(object obj)
    {
        return base.Equals(obj);
    }
}

public class Ledger : Account
{
    public override bool Equals(object obj)
    {
        if (base.Equals(obj))
        {
            return true;
        }
        return false;
    }
}
