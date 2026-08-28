class Labels
{
    string Build()
    {
        var name = " oracle ";
        var digits = 42.ToString();
        var trimmed = name.Trim();
        return digits + trimmed;
    }
}
