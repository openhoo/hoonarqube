public class LoopProbe
{
    private int ticks;

    public void Advance()
    {
        for (int i = 0; i < 10; i++)
        {
            ticks += 1;
        }
    }
}
