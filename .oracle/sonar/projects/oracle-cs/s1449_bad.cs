public class S1449Bad
{
    public int First(string text)
    {
        return text.IndexOf("a");
    }

    public int Last(string text)
    {
        return text.LastIndexOf("a");
    }

    public int Order(string text, string other)
    {
        return text.CompareTo(other);
    }
}
