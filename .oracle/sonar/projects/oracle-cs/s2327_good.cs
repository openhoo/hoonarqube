public class S2327Good
{
    public void Work()
    {
        try
        {
            System.Console.WriteLine("one");
        }
        catch (System.IO.IOException error)
        {
            Heal();
        }

        Gap();

        try
        {
            System.Console.WriteLine("two");
        }
        catch (System.IO.IOException error)
        {
            Heal();
        }
        finally
        {
            Finish();
        }
    }

    private void Heal()
    {
    }

    private void Gap()
    {
    }

    private void Finish()
    {
    }
}
