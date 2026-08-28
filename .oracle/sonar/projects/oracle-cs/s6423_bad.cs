public class ArchiveFunctions
{
    private readonly Microsoft.Extensions.Logging.ILogger logger = null!;

    [Microsoft.Azure.WebJobs.FunctionName("Archive")]
    public void Archive()
    {
        try
        {
            System.IO.File.WriteAllText("archive.txt", "data");
        }
        catch (System.Exception)
        {
            throw;
        }
    }

    [Microsoft.Azure.WebJobs.FunctionName("Compact")]
    public void Compact()
    {
        try
        {
            System.IO.File.WriteAllText("compact.txt", "data");
        }
        catch (System.IO.IOException)
        {
        }
    }
}
