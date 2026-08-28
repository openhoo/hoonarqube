public class S2737Good
{
    public void Work()
    {
        try
        {
            System.Console.WriteLine("work");
        }
        catch (System.InvalidOperationException failure)
        {
            System.Console.WriteLine(failure.Message);
            throw;
        }

        try
        {
            System.Console.WriteLine("more");
        }
        catch (System.IO.IOException io) when (io.Data != null)
        {
            Recover();
        }
    }

    private void Recover()
    {
    }
}
