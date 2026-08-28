public class SpecificCatch
{
    public void Run()
    {
        try
        {
            System.Console.WriteLine("run");
        }
        catch (System.InvalidOperationException)
        {
            System.Console.WriteLine("invalid");
        }
    }
}
