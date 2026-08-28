public class Basket
{
    private readonly System.Collections.Generic.List<string> items = new System.Collections.Generic.List<string>();

    public System.Collections.Generic.List<string> Items
    {
        get { return items.ToList(); }
    }

    public string[] Names
    {
        get { return items.ToArray(); }
    }

    public System.Collections.Generic.List<string> Copy()
    {
        return items.ToList();
    }
}
