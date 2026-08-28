public class Probe
{
    public bool Head(string text)
    {
        return text.StartsWith('a');
    }

    public bool Prefixed(string text)
    {
        return text.StartsWith("ab", System.StringComparison.Ordinal);
    }

    public bool Empty(string text)
    {
        return text.EndsWith("");
    }
}
