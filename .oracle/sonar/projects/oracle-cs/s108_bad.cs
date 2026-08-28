public class Sample
{
    public void Work()
    {
        if (IsReady())
        {
        }
        for (var index = 0; index < 3; index++)
        {
        }
        try
        {
            Work();
        }
        catch (System.Exception)
        {
        }
    }

    private bool IsReady()
    {
        return true;
    }
}
