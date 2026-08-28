public class Sample
{
    private int _ticks;

    public void Drain()
    {
        for (var index = 0; index < 3; index++)
        {
            _ticks++;
        }
    }
}
