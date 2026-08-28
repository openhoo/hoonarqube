public class Sample
{
    public void Work(object gate)
    {
        System.Threading.Monitor.Enter(gate);
        try
        {
            System.Console.WriteLine("critical");
        }
        catch
        {
            System.Threading.Monitor.Exit(gate);
        }
    }
}
