public class InboxFunctions
{
    [Microsoft.Azure.WebJobs.FunctionName("Drain")]
    public void Drain()
    {
        try
        {
            var client = new System.Net.Http.HttpClient();
            System.Console.WriteLine(client.Timeout);
        }
        catch (System.Exception ex)
        {
            _logger.LogError(ex, "drain failed");
        }
    }
}
