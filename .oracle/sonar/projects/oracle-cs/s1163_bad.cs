public class S1163Bad
{
    public void Work(bool done)
    {
        try
        {
            Work(done);
        }
        finally
        {
            throw new InvalidOperationException();
        }

        try
        {
            Work(done);
        }
        finally
        {
            if (done)
            {
                throw new TimeoutException();
            }
        }
    }
}
