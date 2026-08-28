public class Sample
{
    public void Run(int value)
    {
        if (value > 0)
        {
            System.Console.WriteLine("pos");
        }
        else
        {
            System.Console.WriteLine("other");
        }
    }

    public void Check(int x)
    {
        if (x > 0)
        {
            System.Console.WriteLine(x);
        }

        System.Console.WriteLine("gap");

        if (x < 0)
        {
            System.Console.WriteLine(x + 1);
        }
    }
}
