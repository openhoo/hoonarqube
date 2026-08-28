abstract class Gateway
{
    internal void Open(string address)
    {
    }
}

class HttpGateway : Gateway
{
    internal void Open(object address)
    {
    }
}
