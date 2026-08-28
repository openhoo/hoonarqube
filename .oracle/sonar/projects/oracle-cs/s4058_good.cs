public class S4058Good
{
    public bool Same(object first, object second)
    {
        return first.Equals(second);
    }

    public int Order(string left, string right)
    {
        return string.Compare(left, right, System.StringComparison.Ordinal);
    }
}
