public class Formatters
{
    public string Long(System.DateTime value)
    {
        return value.ToString("F");
    }

    public string RoundTrip(System.DateTimeOffset value)
    {
        return value.ToString("O");
    }

    public string Plain(int count)
    {
        return count.ToString();
    }
}
