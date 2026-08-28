class S2629Bad
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger, string name)
    {
        logger.LogInformation($"User {name} logged in");
        logger.LogWarning("Prefix: " + name);
    }
}
