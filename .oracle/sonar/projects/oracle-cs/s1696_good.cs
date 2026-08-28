public class S1696Good
{
    public void Work(int[] data)
    {
        try
        {
            System.Console.WriteLine(data.Length);
        }
        catch (ArgumentNullException other)
        {
            System.Console.WriteLine(other.Message);
        }
        catch
        {
            throw;
        }
    }
}
