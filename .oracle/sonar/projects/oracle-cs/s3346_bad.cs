public class S3346Bad
{
    public void Work(System.Collections.Generic.List<string> animals)
    {
        System.Diagnostics.Debug.Assert(animals.Remove("dog"));
    }
}
