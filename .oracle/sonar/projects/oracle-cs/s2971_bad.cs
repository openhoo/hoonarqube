public class EntryScanner
{
    public int Positive(System.Collections.Generic.List<int> entries)
    {
        return entries.Where(v => v > 0).Count();
    }

    public int Head(System.Collections.Generic.List<int> entries)
    {
        return entries.Where(v => v > 0).FirstOrDefault();
    }

    public bool AnySmall(System.Collections.Generic.List<int> entries)
    {
        return entries.Where(v => v < 9).Any();
    }
}
