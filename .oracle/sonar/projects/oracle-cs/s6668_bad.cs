public class Reporter
{
    public void Report(Microsoft.Extensions.Logging.ILogger logger)
    {
        try
        {
            Work();
        }
        catch (System.IO.IOException exception)
        {
            logger.LogError("Upload failed", exception);
            logger.LogError("Save failed for {Name}", "doc", exception);
        }
    }

    private void Work()
    {
    }
}
