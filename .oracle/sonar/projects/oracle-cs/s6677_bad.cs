class S6677Bad
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogInformation("Request {RequestId} retried as {RequestId}", 1, 2);
    }
}
