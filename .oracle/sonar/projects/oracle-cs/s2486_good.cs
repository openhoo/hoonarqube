public class S2486Good
{
    public void Run(System.Action action)
    {
        try
        {
            action();
        }
        catch (System.InvalidOperationException)
        {
            System.Console.WriteLine("ignored");
        }

        try
        {
            action();
        }
        catch
        {
            System.Console.WriteLine("recovered");
        }
    }
}
