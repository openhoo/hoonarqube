public class S3217Good
{
    public int TotalLength(System.Collections.Generic.List<string> rows)
    {
        int total = 0;
        foreach (string raw in rows)
        {
            total += raw.Length;
        }
        return total;
    }
}
