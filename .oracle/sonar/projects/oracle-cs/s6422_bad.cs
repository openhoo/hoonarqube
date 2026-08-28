public class GateFunctions
{
    [Microsoft.Azure.WebJobs.FunctionName("Gate")]
    public void Gate()
    {
        try
        {
            var task = System.Threading.Tasks.Task.Delay(10);
            task.Wait();
            int result = Fetch().Result;
            System.Console.WriteLine(result);
        }
        catch (System.Exception ex)
        {
            _logger.LogError(ex, "gate failed");
        }
    }

    private static async System.Threading.Tasks.Task<int> Fetch()
    {
        await System.Threading.Tasks.Task.Delay(5);
        return 42;
    }
}
