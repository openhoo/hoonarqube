public class S3998Bad
{
    private readonly System.StackOverflowException gate = new();

    public void Work()
    {
        lock (gate) // S3998
        {
            System.Console.WriteLine("work");
        }
    }
}
