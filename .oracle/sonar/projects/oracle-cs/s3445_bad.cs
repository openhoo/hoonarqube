public class S3445Bad
{
    public void Rethrow(System.Action action)
    {
        try
        {
            action();
        }
        catch (System.InvalidOperationException caught)
        {
            throw caught;
        }
    }
}
