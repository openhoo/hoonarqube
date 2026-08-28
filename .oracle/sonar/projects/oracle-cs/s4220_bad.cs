using System;

public class Publisher
{
    public event EventHandler Received;

    protected virtual void OnReceived(EventArgs args)
    {
        Received?.Invoke(null, args);
    }
}
