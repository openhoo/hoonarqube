using System;

public class Audit
{
    private System.DateTime stamp;

    public void Record()
    {
        stamp = DateTime.Now;
        DateTime modified = DateTime.Now;
    }
}
