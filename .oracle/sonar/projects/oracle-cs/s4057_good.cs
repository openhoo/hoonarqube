public class Parser
{
    public int Parse(string raw)
    {
        return Convert.ToInt32(raw, System.Globalization.CultureInfo.InvariantCulture);
    }

    public int ParseOwn(string raw)
    {
        return int.Parse(raw, System.Globalization.CultureInfo.InvariantCulture);
    }
}
