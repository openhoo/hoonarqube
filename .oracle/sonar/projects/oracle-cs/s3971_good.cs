public class FinalizableBuffer
{
    ~FinalizableBuffer()
    {
    }

    public void Release()
    {
        if (IsPinned())
        {
            Unpin();
        }
    }

    private bool IsPinned()
    {
        return false;
    }

    private void Unpin()
    {
    }
}
