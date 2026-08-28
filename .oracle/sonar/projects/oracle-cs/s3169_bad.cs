public class LedgerSorter
{
    public void Sort(System.Collections.Generic.List<int> entries)
    {
        entries.OrderBy(a => a).OrderBy(b => b).OrderBy(c => c);
        entries.OrderBy(a => a).OrderByDescending(b => b);
    }
}
