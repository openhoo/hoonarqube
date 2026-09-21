public sealed class InstanceService
{
    private const string Prefix = "value:";

    public InstanceService(string value)
    {
        Value = Normalize(value);
    }

    public string Value { get; }

    private static string Normalize(string value)
    {
        return Prefix + value;
    }
}
