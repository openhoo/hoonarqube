class S3416Bad
{
    void Setup()
    {
        var factory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder => { });
        var logger = factory.CreateLogger<UnrelatedService>();
        logger.LogInformation("ready");
    }
}

class UnrelatedService
{
}
