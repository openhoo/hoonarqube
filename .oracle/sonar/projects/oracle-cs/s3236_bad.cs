using System.Runtime.CompilerServices;

class Tracer
{
    void Trace(
        string message,
        [CallerFilePath] string file = "",
        [CallerLineNumber] int line = 0)
    {
    }

    void Run()
    {
        Trace("boot", "Tracer.cs", 12);
    }
}
