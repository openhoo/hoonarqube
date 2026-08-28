public class S1449Good
{
    public int First(string text)
    {
        return text.IndexOf("a", System.StringComparison.Ordinal);
    }

    public int Last(string text)
    {
        return text.LastIndexOf('a', 2);
    }

    public int Order(string text, string other)
    {
        return text.CompareTo(other, System.StringComparison.Ordinal);
    }
}
