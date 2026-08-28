class S6673Good
{
    void Copy(Microsoft.Extensions.Logging.ILogger logger, string source, string target)
    {
        logger.LogInformation("Copying {Source} over {Target}", source, target);
    }
}
