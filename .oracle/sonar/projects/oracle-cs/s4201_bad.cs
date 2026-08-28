public class Sample
{
    public bool Check(object item)
    {
        bool typed = item != null && item is string;
        bool swapped = item == null || !(item is int);
        return typed || swapped;
    }
}
