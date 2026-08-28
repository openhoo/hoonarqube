class Report
{
    public void Filter(System.Collections.Generic.IEnumerable<int> values)
    {
        values.Where(value => value > 0);
    }
}
