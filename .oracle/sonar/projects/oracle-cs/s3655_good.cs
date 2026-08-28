public class Sample
{
    public int Total(int? count)
    {
        if (count.HasValue)
        {
            return count.Value;
        }
        return 0;
    }
}
