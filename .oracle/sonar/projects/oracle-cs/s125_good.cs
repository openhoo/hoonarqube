using System;

/// <summary>Builds plain-text status reports.</summary>
class ReportBuilder
{
    // Builds one report per batch before flushing output.
    void Build(string[] items)
    {
        Console.WriteLine("built");
    }
}
