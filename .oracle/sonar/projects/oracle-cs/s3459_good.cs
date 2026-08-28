class Ledger
{
    private int cached;

    public int Get()
    {
        cached = 42;
        return cached;
    }
}
