class S6667Good
{
    void Run(Microsoft.Extensions.Logging.ILogger logger)
    {
        try
        {
            Work();
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "Operation failed");
        }
    }

    void Work() { }
}
