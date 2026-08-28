public class S112Good
{
    public void Work()
    {
        var fine = new InvalidOperationException("ok");
        var also = new ArgumentNullException("name");
        Log(new ApplicationExceptionWrapper());
    }

    private void Log(object value)
    {
    }
}
