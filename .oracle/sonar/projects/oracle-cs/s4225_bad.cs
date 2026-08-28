public static class Extensions
{
    public static string Describe(this object value)
    {
        return value == null ? "<null>" : value.ToString();
    }
}
