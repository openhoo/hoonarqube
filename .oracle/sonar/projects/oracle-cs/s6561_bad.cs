public class Timer
{
    public double ElapsedMilliseconds()
    {
        var started = DateTime.Now;
        Work();
        return (DateTime.Now - started).TotalMilliseconds; // S6561
    }

    private void Work()
    {
    }
}
