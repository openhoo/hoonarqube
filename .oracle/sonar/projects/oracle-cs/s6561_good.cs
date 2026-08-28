public class Timer
{
    public long ElapsedTicks()
    {
        System.Diagnostics.Stopwatch watch = System.Diagnostics.Stopwatch.StartNew();
        watch.Stop();
        return watch.ElapsedTicks;
    }

    public string CurrentStamp()
    {
        return DateTime.Now.ToString("O");
    }
}
