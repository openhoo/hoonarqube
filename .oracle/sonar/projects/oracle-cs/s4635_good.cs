public class Slicer
{
    public string Tail(string text)
    {
        return text.Substring(2);
    }

    public string Window(string text, int start)
    {
        return text.Substring(start, 3);
    }
}
