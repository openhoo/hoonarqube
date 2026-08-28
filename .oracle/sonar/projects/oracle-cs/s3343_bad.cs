public class S3343Bad
{
    public void Track([CallerMemberName] string member = "", int depth = 1)
    {
    }

    public S3343Bad([CallerLineNumber] int line = 0, string tag = "")
    {
    }
}
