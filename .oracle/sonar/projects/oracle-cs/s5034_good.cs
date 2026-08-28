public class Sample
{
    public async System.Threading.Tasks.Task RunOnce()
    {
        System.Threading.Tasks.ValueTask<int> pending = LoadAsync();
        int value = await pending;
        System.Console.WriteLine(value);
    }

    private async System.Threading.Tasks.ValueTask<int> LoadAsync()
    {
        await System.Threading.Tasks.Task.Delay(1);
        return 7;
    }
}
