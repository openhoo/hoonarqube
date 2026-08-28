public class Slicer
{
    public int Find(string text, int startIndex, char value)
    {
        return text.Substring(startIndex).IndexOf(value);
    }
}
