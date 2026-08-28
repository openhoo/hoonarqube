public class DateReader
{
    public System.DateTime Read(string text)
    {
        return System.DateTime.Parse(text);
    }

    public bool TryRead(string text, out System.DateTime value)
    {
        return System.DateTime.TryParse(text, out value);
    }
}
