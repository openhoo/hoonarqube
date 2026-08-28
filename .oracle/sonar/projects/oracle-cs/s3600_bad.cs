class Sender
{
    public virtual void Send(int lead, int[] rest)
    {
    }
}

class Relay : Sender
{
    public override void Send(int lead, params int[] rest)
    {
    }
}
