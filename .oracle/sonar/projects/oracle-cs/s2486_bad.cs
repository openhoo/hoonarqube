public class S2486Bad
{
    public void Run(System.Action action)
    {
        try
        {
            action();
        }
        catch (System.Exception)
        {
            // Nothing to do.
        }

        try
        {
            action();
        }
        catch (Exception swallowed) { }
    }
}
