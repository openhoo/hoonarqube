public class Merger
{
    public void MergeAll()
    {
        var items = new System.Collections.Generic.HashSet<int>();
        items.UnionWith(items);
    }
}
