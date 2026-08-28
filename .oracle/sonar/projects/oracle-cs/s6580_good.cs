public class DateReader
{
    public System.DateTime Read(string text)
    {
        return System.DateTime.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
    }

    public bool TryRead(string text, out System.DateTime value)
    {
        return System.DateTime.TryParse(text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out value);
    }
}
