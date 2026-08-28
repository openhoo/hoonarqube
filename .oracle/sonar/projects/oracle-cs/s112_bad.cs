public class S112Bad
{
    public void Work()
    {
        throw new Exception("boom");
        throw new System.ApplicationException("wrapped");
        var wrapper = new ApplicationExceptionWrapper();
        var fine = new InvalidOperationException("ok");
    }

    private void Log(object value)
    {
    }
}
