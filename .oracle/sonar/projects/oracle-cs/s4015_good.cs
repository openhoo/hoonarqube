class Publisher
{
    public virtual void Broadcast(string topic)
    {
    }
}

class RadioPublisher : Publisher
{
    public override void Broadcast(string topic)
    {
    }
}
