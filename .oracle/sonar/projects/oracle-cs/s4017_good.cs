public class Catalog
{
    public System.Collections.Generic.Dictionary<string, int> Count(System.Collections.Generic.IEnumerable<string> names)
    {
        return new System.Collections.Generic.Dictionary<string, int>();
    }

    public TResult Map<TResult>(System.Collections.Generic.Dictionary<string, TResult> source)
    {
        return default(TResult);
    }

    public System.Collections.Generic.List<int>[] Pages()
    {
        return new System.Collections.Generic.List<int>[0];
    }
}
