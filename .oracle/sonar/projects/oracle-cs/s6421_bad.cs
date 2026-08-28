public class ReportFunctions
{
    [Microsoft.Azure.WebJobs.FunctionName("Build")]
    public void Build()
    {
        System.Console.WriteLine("building");
    }

    [Microsoft.Azure.WebJobs.FunctionName("Send")]
    public async System.Threading.Tasks.Task Send()
    {
        await System.Threading.Tasks.Task.Delay(10);
    }
}
