public class CounterFunctions
{
    private const string Label = "counter";
    private int total;

    [Microsoft.Azure.WebJobs.FunctionName("Count")]
    public void Count()
    {
        try
        {
            total++;
            System.Console.WriteLine(Label);
        }
        catch (System.Exception ex)
        {
            _logger.LogError(ex, "count failed");
        }
    }
}
