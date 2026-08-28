public class S2139Bad
{
    private Microsoft.Extensions.Logging.ILogger logger;

    public void Run(System.Action action)
    {
        try
        {
            action();
        }
        catch (System.InvalidOperationException failure)
        {
            logger.LogError("Failed {Code}", failure);
            throw;
        }
    }
}
