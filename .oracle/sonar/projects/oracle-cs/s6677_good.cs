class S6677Good
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogInformation("Request {RequestId} handled for {User}", 1, "amy");
    }
}
