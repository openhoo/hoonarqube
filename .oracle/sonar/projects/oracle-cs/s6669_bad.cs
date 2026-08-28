public class Worker
{
    private Microsoft.Extensions.Logging.ILogger audit;

    private OracleLogger eventLog;

    public Microsoft.Extensions.Logging.ILogger LogWriter { get; set; }
}
