public sealed class Widget
{
    private Widget()
    {
    }

    public Widget(string name)
    {
        Name = name;
    }

    protected string Name { get; }
}
