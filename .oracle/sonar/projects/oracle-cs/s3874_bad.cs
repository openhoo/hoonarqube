public class ReportBuilder
{
    public int Build(out string title, ref int revisions)
    {
        title = string.Empty;
        return revisions;
    }

    internal bool TryLoad(string path, out byte[] payload)
    {
        payload = new byte[0];
        return true;
    }
}
