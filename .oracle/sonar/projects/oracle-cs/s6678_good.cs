class S6678Good
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogInformation("User {Name} at {IpAddress}", "amy", "10.0.0.1");
        logger.LogDebug("Slot {0} reused", 3);
    }
}
