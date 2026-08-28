public class S4586Bad
{
    public Task First(bool ready)
    {
        if (ready)
        {
            return null;
        }

        return Task.CompletedTask;
    }

    private Task<int> Second()
    {
        return null;
    }
}
