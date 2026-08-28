public class DisposableWidget
{
    protected void Dispose()
    {
    }
}

public class Widget : DisposableWidget
{
    public Widget()
    {
    }

    ~Widget()
    {
        base.Dispose();
    }
}
