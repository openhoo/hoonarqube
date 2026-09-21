public sealed class StructuredLogging
{
    public void Report(dynamic logger, Exception exception, string id)
    {
        logger.LogWarning(exception, "Operation {Id} failed.", id);
    }
}
