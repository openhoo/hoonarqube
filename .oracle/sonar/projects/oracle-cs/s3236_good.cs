class Tracer
{
    void Trace(string message, [CallerMemberName] string member = "")
    {
    }

    void Run()
    {
        Trace("boot");
    }
}
