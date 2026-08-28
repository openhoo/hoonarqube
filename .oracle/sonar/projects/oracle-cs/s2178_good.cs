public class Gate
{
    public bool Open(int maskA, int maskB)
    {
        if ((maskA & maskB) != 0)
        {
            return true;
        }
        if (IsReady && HasItems || !ShouldRetry)
        {
            return false;
        }
        int combined = maskA | maskB;
        return combined > 0;
    }
}
