public class FinalizableBuffer
{
    ~FinalizableBuffer()
    {
    }

    public void Release()
    {
        System.GC.SuppressFinalize(this);
        if (IsPinned())
        {
            GC.SuppressFinalize(this);
        }
    }

    private bool IsPinned()
    {
        return false;
    }
}
