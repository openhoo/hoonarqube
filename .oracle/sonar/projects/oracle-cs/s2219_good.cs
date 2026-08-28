public class Sample
{
    public void Check(object item)
    {
        if (item is string text)
        {
            System.Console.WriteLine(text.Length);
        }

        System.Type known = typeof(string);
        System.Type runtime = item.GetType();
        System.Console.WriteLine(known != runtime);
    }
}
