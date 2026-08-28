class S6675Bad
{
    void Emit(System.Diagnostics.TraceSwitch level)
    {
        System.Diagnostics.Trace.WriteLineIf(level.TraceError, "error path");
        System.Diagnostics.Trace.WriteLineIf(level.TraceWarning, "warning path");
    }
}
