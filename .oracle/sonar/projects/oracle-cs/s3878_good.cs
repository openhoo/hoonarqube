public class S3878Good
{
    public void Run()
    {
        var text = string.Format("{0} {1}", "a", "b");
        var joined = string.Join(",", "a", "b");
    }
}
