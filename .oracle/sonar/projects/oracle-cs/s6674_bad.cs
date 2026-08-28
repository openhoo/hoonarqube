class S6674Bad
{
    void Emit(Microsoft.Extensions.Logging.ILogger logger)
    {
        logger.LogInformation("Order {Id placed");
        logger.LogWarning("Pair {} empty");
        logger.LogError("Stray close } here");
    }
}
