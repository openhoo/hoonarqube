public class Sample
{
    public void Run(int value)
    {
        if (value > 0)
        {
            System.Console.WriteLine("pos");
        }
        else if (value < 0)
        {
            System.Console.WriteLine("neg");
        }
        else if (value > 0)
        {
            System.Console.WriteLine("repeat");
        }
    }

    public void Second(int y)
    {
        if (y < 3)
        {
            System.Console.WriteLine("run");
        }
        else if (y < 3)
        {
            System.Console.WriteLine("walk");
        }
    }
}
