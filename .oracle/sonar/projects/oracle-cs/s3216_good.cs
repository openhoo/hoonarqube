public class Runner
{
    public async System.Threading.Tasks.Task Run(System.Threading.Tasks.Task work)
    {
        await work.ConfigureAwait(false);
        await work.ConfigureAwait(false);
    }
}
