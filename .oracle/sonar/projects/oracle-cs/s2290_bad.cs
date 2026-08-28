class S2290Bad
{
    public delegate void ChangedHandler(object sender);

    public virtual event ChangedHandler Changed;

    internal virtual event ChangedHandler Resetting;
}
