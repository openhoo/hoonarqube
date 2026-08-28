public class LedgerQuery
{
    public void Query(System.Collections.Generic.List<int> entries)
    {
        entries.OrderByDescending(v => v).Where(v => v > 0);
        entries.OrderBy(v => v).Where(v => v < 9);
        entries.OrderBy(v => -v).Where(v => v != 0);
    }
}
