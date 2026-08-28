public class Jobs
{
    public async System.Threading.Tasks.Task RunMigration()
    {
        await System.Threading.Tasks.Task.Delay(10);
    }

    public System.Threading.Tasks.Task FetchAsync()
    {
        return System.Threading.Tasks.Task.CompletedTask;
    }
}
