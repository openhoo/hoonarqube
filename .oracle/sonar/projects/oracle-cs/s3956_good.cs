public class S3956Good
{
    private List<int> items = new List<int>();

    private List<int> Peek()
    {
        return items;
    }

    internal int Total(List<int> xs)
    {
        return xs.Count;
    }
}
