public class Account : System.IDisposable
{
    public void Dispose()
    {
    }

    public override int GetHashCode()
    {
        return base.GetHashCode();
    }

    public bool Same(object obj)
    {
        return base.Equals(obj);
    }
}
