public class S2327Bad
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

        try
        {
            System.Console.WriteLine("two");
        }
        catch (System.IO.IOException error)
        {
            Heal();
        }

        try
        {
            System.Console.WriteLine("three");
        }
        catch (System.IO.IOException error)
        {
            Heal();
        }
    }

    private void Heal()
    {
    }
}
