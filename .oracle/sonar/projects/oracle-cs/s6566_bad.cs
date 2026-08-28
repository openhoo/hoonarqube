using System;

public class Ledger
{
    private DateTimeOffset recordedAt;

    public void Mark(DateTimeOffset expires)
    {
        DateTimeOffset changed = DateTime.Now;
        recordedAt = DateTime.Now;
        expires = DateTime.Now;
    }
}
