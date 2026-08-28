public class Sample
{
    public bool LacksOne(System.Collections.Generic.List<int> items)
    {
        return items.All(v => v != 1);
    }

    public bool HasOne(System.Collections.Generic.List<int> items)
    {
        return items.Contains(1);
    }
}
