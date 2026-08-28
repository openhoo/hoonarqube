class S3416Good
{
    void Setup()
    {
        var factory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder => { });
        var logger = factory.CreateLogger<S3416Good>();
        logger.LogInformation("ready");
    }
}
