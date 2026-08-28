class S6674Good
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogInformation("User {Name} signed in from {Ip}", "amy", "10.0.0.1");
        logger.LogWarning("No placeholders here");
    }
}
