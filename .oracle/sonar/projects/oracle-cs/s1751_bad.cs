public class Sample
{
    public void Once()
    {
        while (System.Console.KeyAvailable)
        {
            System.Console.WriteLine("step");
            break;
        }
    }
}
