public class S1696Bad
{
    public void Work(int[] data)
    {
        try
        {
            System.Console.WriteLine(data.Length);
        }
        catch (NullReferenceException first)
        {
            System.Console.WriteLine(first.Message);
        }

        try
        {
            System.Console.WriteLine(data.Length);
        }
        catch (System.NullReferenceException second) when (second.InnerException == null)
        {
            throw;
        }
    }
}
