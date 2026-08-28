public class Clock
{
    private readonly TimeProvider timeProvider;

    public Clock(TimeProvider timeProvider)
    {
        this.timeProvider = timeProvider;
    }

    public string Stamp()
    {
        return timeProvider.GetLocalNow().ToString("O");
    }
}
