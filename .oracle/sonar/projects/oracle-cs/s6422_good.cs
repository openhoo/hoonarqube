public class GateFunctions
{
    private readonly Microsoft.Extensions.Logging.ILogger logger;

    [Microsoft.Azure.WebJobs.FunctionName("Gate")]
    public async System.Threading.Tasks.Task Gate()
    {
        try
        {
            await System.Threading.Tasks.Task.Delay(10);
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "gate failed");
        }
    }
}
