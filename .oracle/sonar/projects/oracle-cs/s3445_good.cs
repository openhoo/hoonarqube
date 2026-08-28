public class S3445Good
{
    public void Wrap(System.InvalidOperationException failure)
    {
        if (failure != null)
        {
            throw new System.InvalidOperationException("wrapped", failure);
        }
    }

    public void Rethrow(System.Action action)
    {
        try
        {
            action();
        }
        catch (System.InvalidOperationException)
        {
            throw;
        }
    }
}
