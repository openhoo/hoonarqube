class S2629Good
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogInformation("User {Name} logged in", "amy");
        logger.LogWarning("Disk space low on {Drive}", "C");
    }
}
