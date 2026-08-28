public class Sample
{
    private int count;

    public string Name { get; set; }

    public int Compute()
    {
        int items = 5;
        count = items;
        Name = "kept";
        string label = Name + items;
        return count + label.Length;
    }
}
