class S1312Bad
{
    private Microsoft.Extensions.Logging.ILogger logger;

    internal static readonly Microsoft.Extensions.Logging.ILogger audit =
        Microsoft.Extensions.Logging.LoggerFactory.Create(builder => { }).CreateLogger(typeof(S1312Bad));
}
