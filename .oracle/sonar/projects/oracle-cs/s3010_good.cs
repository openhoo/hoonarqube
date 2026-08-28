public class Counter
{
    private static int created;

    private string label;

    static Counter()
    {
        created = 0;
    }

    public Counter(string label)
    {
        this.label = label;
    }
}
