class Sender
{
    public virtual void Send(int lead, params int[] tail)
    {
    }
}

class Relay : Sender
{
    public override void Send(int lead, params int[] tail)
    {
    }
}
