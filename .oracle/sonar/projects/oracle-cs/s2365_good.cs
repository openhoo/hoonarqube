public class Basket
{
    private readonly System.Collections.Generic.List<string> items = new System.Collections.Generic.List<string>();

    public System.Collections.Generic.List<string> Items
    {
        get { return items; }
    }

    public System.Collections.Generic.List<string> Backing
    {
        set
        {
            items.Clear();
            items.AddRange(value);
        }
    }

    public System.Collections.Generic.IReadOnlyCollection<string> Snapshot()
    {
        return items.AsReadOnly();
    }
}
