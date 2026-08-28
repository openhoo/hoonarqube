public class LedgerSorter
{
    public void Sort(System.Collections.Generic.List<int> entries)
    {
        entries.GroupBy(a => a % 3).OrderBy(b => b.Key);
        entries.OrderBy(a => a).Select(v => v * 2);
    }
}
