class S2290Good
{
    public delegate void ChangedHandler(object sender);

    private ChangedHandler changedStore;

    public virtual event ChangedHandler Changed
    {
        add { changedStore += value; }
        remove { changedStore -= value; }
    }

    internal event ChangedHandler Resetting;
}
