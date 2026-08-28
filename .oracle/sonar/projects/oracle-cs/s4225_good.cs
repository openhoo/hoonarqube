public static class Extensions
{
    public static bool IsBlank(this string value)
    {
        return string.IsNullOrWhiteSpace(value);
    }
}
