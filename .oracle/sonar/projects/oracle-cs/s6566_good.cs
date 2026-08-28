using System;

public class Ledger
{
    private DateTimeOffset recordedAt;

    public void Mark(DateTimeOffset expires)
    {
        DateTimeOffset changed = DateTimeOffset.Now;
        recordedAt = DateTimeOffset.UtcNow;
    }
}
