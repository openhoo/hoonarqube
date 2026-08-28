public class ResourceGuard : System.IDisposable
{
    public void Dispose(bool failFast)
    {
        if (failFast)
        {
            throw new System.InvalidOperationException("failed");
        }
        throw new System.Exception("dispose failed");
    }

    public void Dispose()
    {
        Dispose(false);
    }

    public override string ToString()
    {
        if (IsBroken())
        {
            throw new System.Exception("broken");
        }
        return "guard";
    }

    private bool IsBroken()
    {
        return false;
    }
}
