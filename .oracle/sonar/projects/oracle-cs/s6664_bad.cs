class S6664Bad
{
    void Chatty(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogWarning("first warning");
        logger.LogWarning("second warning");
        logger.LogWarning("third warning");
    }
}
