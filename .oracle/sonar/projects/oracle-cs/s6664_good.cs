class S6664Good
{
    void Chatty(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogDebug("one");
        logger.LogDebug("two");
        logger.LogInformation("summary ready");
        logger.LogWarning("only one warning allowed");
    }
}
