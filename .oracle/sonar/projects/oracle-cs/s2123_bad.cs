public class Sample
{
    public int Tally()
    {
        int ticks = System.Environment.TickCount;
        ticks = ticks++;
        return ticks--;
    }
}
