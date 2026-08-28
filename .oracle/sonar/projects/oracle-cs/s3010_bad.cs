public class Counter
{
    private static int created;

    private string label;

    public Counter(string label)
    {
        created = 0;
        this.label = label;
    }
}
