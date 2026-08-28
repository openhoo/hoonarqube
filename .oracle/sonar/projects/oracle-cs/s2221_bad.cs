public class S2221Bad
{
    public void Run(System.Action action)
    {
        try
        {
            action();
        }
        catch (System.Exception failure)
        {
            System.Console.WriteLine(failure.Message);
        }

        try
        {
            action();
        }
        catch (Exception other)
        {
            System.Console.WriteLine(other.Message);
        }
    }
}
