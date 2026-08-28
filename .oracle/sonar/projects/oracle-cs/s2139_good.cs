public class S2139Good
{
    private Microsoft.Extensions.Logging.ILogger logger;

    public void LogOnly(System.Action action)
    {
        try
        {
            action();
        }
        catch (System.InvalidOperationException failure)
        {
            logger.LogWarning("Skipped {Code}", failure);
        }
    }

    public void RethrowAfterMark(System.Action action)
    {
        try
        {
            action();
        }
        catch (System.InvalidOperationException failure)
        {
            System.Console.WriteLine(failure.Message);
            throw;
        }
    }
}
