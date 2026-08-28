public class S6507Good
{
    private readonly object field = new object();

    public void Work(object gate)
    {
        lock (gate)
        {
            System.Console.WriteLine("parameter");
        }

        lock (field)
        {
            System.Console.WriteLine("field");
        }
    }
}
