class Report
{
    private int draftCount;

    public string Publish()
    {
        return BuildBody();
    }

    private string BuildBody()
    {
        draftCount += 1;
        return draftCount.ToString();
    }
}
