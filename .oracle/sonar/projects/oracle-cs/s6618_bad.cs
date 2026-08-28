public class Formatter
{
    public string InvariantText(int value)
    {
        return System.FormattableString.Invariant($"v={value}");
    }

    public string CurrentText(int value)
    {
        return System.FormattableString.CurrentCulture($"v={value}");
    }
}
