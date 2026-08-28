class S6678Bad
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogInformation("User {name} at {ipAddress}", "amy", "10.0.0.1");
    }
}
