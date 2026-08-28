public class Sample
{
    private int count;

    public string Name { get; set; }

    public int Compute()
    {
        int count = 5;
        string Name = "x";
        return count + Name.Length;
    }
}
