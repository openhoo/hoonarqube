using System.Diagnostics.Contracts;

public class Sample
{
    [Pure]
    public void Log(string message)
    {
        System.Console.WriteLine(message);
    }

    [PureAttribute]
    public void Flush()
    {
    }
}
