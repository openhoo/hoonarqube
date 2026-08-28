public class ReportFunctions
{
    private readonly Microsoft.Extensions.Logging.ILogger logger;

    [Microsoft.Azure.WebJobs.FunctionName("Build")]
    public void Build()
    {
        try
        {
            System.Console.WriteLine("building");
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "build failed");
        }
    }
}
