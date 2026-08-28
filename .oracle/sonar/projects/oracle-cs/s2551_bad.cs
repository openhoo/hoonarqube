class Gatekeeper
{
    private readonly object sharedGate = new object();

    void Work()
    {
        lock (this)
        {
            lock ("inner")
            {
            }
        }
        lock (typeof(Gatekeeper))
        {
        }
        lock (sharedGate)
        {
        }
    }
}
