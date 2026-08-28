public class Sample
{
    public int Tally()
    {
        int ticks = System.Environment.TickCount;
        System.Console.WriteLine(ticks);
        ticks++;
        return ticks;
    }
}
