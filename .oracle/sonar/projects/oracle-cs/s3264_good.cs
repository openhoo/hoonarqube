class Telemetry
{
    public event System.EventHandler Completed;

    public void Finish()
    {
        Completed(this, System.EventArgs.Empty);
    }
}
