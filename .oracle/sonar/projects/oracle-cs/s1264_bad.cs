public class Sample
{
    private int _ticks;

    public void Drain()
    {
        var index = 0;
        for (; index < 3; )
        {
            index++;
        }
        _ticks = index;
    }
}
