class Registry
{
    public void Register()
    {
        var ids = new List<int>();
        ids.Add(1);
        var only = ids.SingleOrDefault();
        var first = ids.FirstOrDefault();
    }
}
