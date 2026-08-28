class BaseLogger
{
    protected virtual void Write(string message = "none")
    {
    }
}

class FileLogger : BaseLogger
{
    protected override void Write(string message = "none")
    {
        base.Write("flush");
    }
}
