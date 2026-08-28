public class Sample
{
    public bool HasTwo(System.Collections.Generic.List<int> items)
    {
        return items.Any(v => v == 2);
    }

    public bool AllOne(System.Collections.Generic.List<int> items)
    {
        return items.All(v => 1 == v);
    }
}
