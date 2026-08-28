public class Sample
{
    public bool Gate(bool ready)
    {
        if (ready)
        {
            System.Console.WriteLine("maybe");
        }
        return ready;
    }
}
