class Gatekeeper
{
    private readonly object sharedGate = new object();

    void Work()
    {
        lock (sharedGate)
        {
        }
    }
}
