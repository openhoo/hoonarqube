public class S2445Good
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
