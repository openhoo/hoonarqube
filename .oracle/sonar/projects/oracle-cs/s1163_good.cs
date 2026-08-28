public class S1163Good
{
    public void Work(bool done)
    {
        try
        {
            Work(done);
        }
        catch (System.IO.IOException failure)
        {
            throw;
        }

        if (done)
        {
            throw new TimeoutException();
        }
    }
}
