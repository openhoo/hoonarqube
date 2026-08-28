public class Store
{
    public TEntity Load<TEntity>(TEntity existing, int id)
    {
        return existing;
    }

    public bool TryPair<TLeft, TRight>(TLeft left, TRight right)
    {
        return Equals(left, right);
    }

    public int Plain(int value)
    {
        return value;
    }
}
