using System;

[Flags]
public enum Options
{
    None = 0,
    Read = 1,
    Write = 2
}

public class Gate
{
    public bool CanRead(Options options)
    {
        return (options & Options.Read) != Options.None;
    }
}
