public class S4586Good
{
    public async Task First(bool ready)
    {
        if (ready)
        {
            await Task.Yield();
        }
    }

    public Task Second()
    {
        return Task.CompletedTask;
    }

    private int Plain()
    {
        return 1;
    }
}
