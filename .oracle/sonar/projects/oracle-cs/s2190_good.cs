public class Sample
{
    public void Poll()
    {
        while (true)
        {
            if (System.Console.KeyAvailable)
            {
                break;
            }
        }
    }
}
