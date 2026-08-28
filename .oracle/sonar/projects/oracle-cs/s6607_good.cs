public class LedgerQuery
{
    public void Query(System.Collections.Generic.List<int> entries)
    {
        entries.Where(v => v > 0).OrderBy(v => v);
        entries.GroupBy(v => v % 2).OrderBy(g => g.Key);
    }
}
