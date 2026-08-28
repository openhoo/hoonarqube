public class Collector
{
    private int seen;

    public void Gather(int[] items, System.Collections.Generic.List<int> result)
    {
        foreach (var item in items.Where(item => item > 0))
        {
            result.Add(item);
            seen = seen + 1;
        }

        foreach (var item in items)
        {
            if (item > 0)
            {
                result.Add(item);
            }
            else
            {
                result.Remove(item);
            }
        }
    }
}
