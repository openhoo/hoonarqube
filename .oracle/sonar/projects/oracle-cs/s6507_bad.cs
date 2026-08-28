public class S6507Bad
{
    public void Work()
    {
        var gate = new object();
        lock (gate)
        {
            System.Console.WriteLine("first");
        }

        lock (gate)
        {
            System.Console.WriteLine("second");
        }
    }
}
