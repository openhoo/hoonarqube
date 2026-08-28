public class Greeter
{
    public void Talk(System.IO.TextWriter writer)
    {
        writer.WriteLine("entry");
        System.Diagnostics.Debug.Write("trace");
    }
}
