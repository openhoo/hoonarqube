public class InboxFunctions
{
    private static readonly System.Net.Http.HttpClient client = new();

    [Microsoft.Azure.WebJobs.FunctionName("Drain")]
    public void Drain()
    {
        try
        {
            System.Console.WriteLine(client.Timeout);
        }
        catch (System.Exception ex)
        {
            _logger.LogError(ex, "drain failed");
        }
    }
}
