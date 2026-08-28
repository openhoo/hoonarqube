public class ArchiveFunctions
{
    private readonly Microsoft.Extensions.Logging.ILogger logger;

    [Microsoft.Azure.WebJobs.FunctionName("Archive")]
    public void Archive()
    {
        try
        {
            System.IO.File.WriteAllText("archive.txt", "data");
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "archive failed");
        }
    }
}
