public class S2445Bad
{
    private static object shared;

    public void Work()
    {
        lock (shared)
        {
            System.Console.WriteLine("guarded");
        }
    }
}
