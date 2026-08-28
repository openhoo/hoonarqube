class Registry
{
    public void Register()
    {
        var ids = LoadIds();
        var only = ids.SingleOrDefault();
    }
}
