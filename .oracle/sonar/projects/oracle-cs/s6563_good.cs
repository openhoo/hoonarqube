using System;

public class Audit
{
    private System.DateTime stamp;

    public void Record()
    {
        stamp = DateTime.UtcNow;
        string label = "Now";
        int count = 0;
    }
}
