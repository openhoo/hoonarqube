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
            logger.LogError(exception, "Upload failed");
            logger.LogWarning("Retrying {Attempt}", 2);
        }
    }

    private void Work()
    {
    }
}
