using System.Diagnostics.Contracts;

public class Sample
{
    [Pure]
    public int Compute(int value) => value * 2;

    [Pure]
    public string NameOf(int id) => $"id-{id}";

    public void ImpureLog(string message)
    {
        System.Console.WriteLine(message);
    }

    [Obsolete]
    public void LegacyFlush()
    {
    }
}
