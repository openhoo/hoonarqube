public class S2737Bad
{
    public void Work()
    {
        try
        {
            System.Console.WriteLine("work");
        }
        catch
        {
            throw;
        }

        try
        {
            System.Console.WriteLine("more");
        }
        catch (System.InvalidOperationException typed)
        {
            throw typed;
        }
    }
}
