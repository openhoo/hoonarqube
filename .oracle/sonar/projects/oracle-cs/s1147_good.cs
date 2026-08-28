public class Shutdown
{
    public int Finish(bool failed)
    {
        if (failed)
        {
            throw new System.InvalidOperationException("failed");
        }
        return 0;
    }
}
