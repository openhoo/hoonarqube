class S6675Good
{
    void Emit(System.Diagnostics.TraceSwitch level)
    {
        var enabled = level.TraceVerbose;
        System.Diagnostics.Trace.WriteLineIf(enabled, "verbose output");
    }
}
