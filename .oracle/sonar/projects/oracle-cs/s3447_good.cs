public class S3447Good
{
    public bool TryRead(ref string buffer)
    {
        return true;
    }

    public void Fill(out int seed)
    {
        seed = 0;
    }

    public void Load([Optional] string fallback)
    {
    }
}
