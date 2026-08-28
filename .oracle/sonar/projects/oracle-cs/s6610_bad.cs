public class Probe
{
    public bool Head(string text)
    {
        return text.StartsWith("a");
    }

    public bool Tail(string text)
    {
        return text.EndsWith("z");
    }
}
