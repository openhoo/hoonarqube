public class Sample
{
    public async System.Threading.Tasks.Task Run()
    {
        System.Threading.Tasks.ValueTask<int> pending = LoadAsync();
        int first = await pending;
        int second = await pending;
        System.Console.WriteLine(first + second);
    }

    private async System.Threading.Tasks.ValueTask<int> LoadAsync()
    {
        await System.Threading.Tasks.Task.Delay(1);
        return 7;
    }
}
