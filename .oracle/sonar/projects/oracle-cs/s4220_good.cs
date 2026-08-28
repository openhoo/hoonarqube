public delegate void MessageHandler(ReceivedEventArgs payload);

public class ReceivedEventArgs
{
}

public class Publisher
{
    public event MessageHandler Received;
}
