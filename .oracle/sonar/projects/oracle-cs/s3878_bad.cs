public class S3878Bad
{
    public void Run()
    {
        var text = string.Format("{0}", new[] { "a" });
        var joined = string.Join(",", new string[] { "b" });
    }
}
