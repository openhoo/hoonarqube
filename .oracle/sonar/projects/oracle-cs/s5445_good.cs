public class Sample
{
    public void Unpredictable()
    {
        var dir = System.IO.Path.GetTempPath();
        var random = System.IO.Path.Combine(dir, System.IO.Path.GetRandomFileName());
        var bare = GetTempFileName();
        System.IO.File.WriteAllText(random + bare, "payload");
    }

    private static string GetTempFileName() => System.IO.Path.GetRandomFileName();
}
