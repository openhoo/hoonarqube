public class EntryScanner
{
    public int Total(System.Collections.Generic.List<int> entries)
    {
        return entries.Count(v => v > 0);
    }

    public int DoubledCount(System.Collections.Generic.List<int> entries)
    {
        return entries.Where(v => v > 0).Select(v => v * 2).Count();
    }

    public int Head(System.Collections.Generic.List<int> entries)
    {
        return entries.FirstOrDefault(v => v > 0);
    }
}
