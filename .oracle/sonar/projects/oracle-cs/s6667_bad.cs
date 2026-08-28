class S6667Bad
{
    void Run(Microsoft.Extensions.Logging.ILogger logger)
    {
        try
        {
            Work();
        }
        catch (System.Exception ex)
        {
            logger.LogError("Operation failed without detail");
        }
    }

    void Work() { }
}
