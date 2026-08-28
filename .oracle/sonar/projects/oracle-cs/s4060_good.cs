internal sealed class TagAttribute : Attribute
{
}

internal abstract class ScopeAttribute : Attribute
{
}

internal class Registry
{
    public static int Count { get; set; }
}
