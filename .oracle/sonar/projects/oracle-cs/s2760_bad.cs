public class Sample
{
    public void Run(int value)
    {
        if (value > 0)
        {
            System.Console.WriteLine("first");
        }

        if (value > 0)
        {
            System.Console.WriteLine("second");
        }
    }

    public void Check(bool gate)
    {
        if (gate)
        {
            System.Console.WriteLine("a");
        }

        if (gate)
        {
            System.Console.WriteLine("b");
        }
    }
}
