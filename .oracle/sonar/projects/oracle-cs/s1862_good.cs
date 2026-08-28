public class Sample
{
    public void Run(int value)
    {
        if (value > 0)
        {
            if (value > 100)
            {
                System.Console.WriteLine("big");
            }
        }
        else if (value < 0)
        {
            System.Console.WriteLine("neg");
        }
    }
}
