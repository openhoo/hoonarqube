public class CounterFunctions
{
    private static int hits;
    private static string last = "";

    [Microsoft.Azure.WebJobs.FunctionName("Count")]
    public void Count()
    {
        try
        {
            hits++;
            last = System.Console.ReadLine() ?? "";
            System.Console.WriteLine(last);
        }
        catch (System.Exception ex)
        {
            _logger.LogError(ex, "count failed");
        }
    }
}
