class ReportBuilder
{
    private string Build(string title, int depth)
    {
        return depth > 0 ? title : title.ToLowerInvariant();
    }
}
