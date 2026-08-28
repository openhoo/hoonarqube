class S6673Bad
{
    void Copy(Microsoft.Extensions.Logging.ILogger logger, string source, string target)
    {
        logger.LogInformation("Copying {Target} over {Source}", source, target);
    }
}
