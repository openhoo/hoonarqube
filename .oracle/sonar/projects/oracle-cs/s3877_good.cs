public class ResourceGuard
{
    public void DisposeAll()
    {
        throw new System.Exception("cleanup failed");
    }

    public string Describe()
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
