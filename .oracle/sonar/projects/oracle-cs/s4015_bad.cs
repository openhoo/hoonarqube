class Publisher
{
    public virtual void Broadcast(string topic)
    {
    }
}

class RadioPublisher : Publisher
{
    private void Broadcast(string topic)
    {
    }
}
