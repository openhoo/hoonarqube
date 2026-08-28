public class Gate
{
    public bool Open()
    {
        if (IsReady | HasItems)
        {
            return true;
        }
        if (!ShouldRetry & CanFail)
        {
            return false;
        }
        return true;
    }
}
