public class S3346Good
{
    public void Work(int total, int expected)
    {
        Trace.Assert(total > 0);
        Debug.WriteLine(Compute());
        Debug.Assert(total == expected);
    }

    private int Compute()
    {
        return 1;
    }
}
