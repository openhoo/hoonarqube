public class S2302Good
{
    private string tag = "fallback";

    public void Render(string label)
    {
        System.Console.WriteLine(label + ":");
        System.Console.WriteLine("label with space");
        System.Console.WriteLine("1st");
        System.Console.WriteLine(nameof(label));
    }
}
