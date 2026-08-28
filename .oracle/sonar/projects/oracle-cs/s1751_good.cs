public class Sample
{
    public void Drain(bool stop)
    {
        while (System.Console.KeyAvailable)
        {
            if (stop)
            {
                break;
            }
            System.Console.ReadKey();
        }
    }
}
