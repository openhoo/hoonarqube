public class S3343Good
{
    public void Track(int depth, [CallerMemberName] string member = "")
    {
    }

    public void Write(string message, [CallerMemberName] string member = "")
    {
    }

    public void Plain(string message, int depth)
    {
    }
}
