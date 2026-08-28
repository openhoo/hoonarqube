public class Sample
{
    private const string Code = "secret";
    private int callCount;

    public string GetCode()
    {
        callCount++;
        return Code;
    }

    public string GetName()
    {
        callCount++;
        return Code;
    }
}
