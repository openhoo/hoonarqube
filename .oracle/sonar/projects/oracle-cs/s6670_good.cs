class S6670Good
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogInformation("structured output");
        System.Diagnostics.Debug.WriteLine("debug output");
    }
}
