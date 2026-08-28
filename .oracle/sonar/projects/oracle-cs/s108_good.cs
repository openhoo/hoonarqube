public class Sample
{
    private int _ticks;

    public void Work()
    {
        if (IsReady())
        {
            _ticks++;
        }
        for (var index = 0; index < 3; index++)
        {
            _ticks++;
        }
        try
        {
            _ticks--;
        }
        catch (System.Exception)
        {
            _ticks = 0;
        }
    }

    private bool IsReady()
    {
        return true;
    }
}
