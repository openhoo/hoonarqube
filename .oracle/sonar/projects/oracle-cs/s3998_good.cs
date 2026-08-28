public class S3998Good
{
    private readonly object gate = new object();

    public void Work()
    {
        lock (gate)
        {
            System.Console.WriteLine("guarded");
        }
    }
}
