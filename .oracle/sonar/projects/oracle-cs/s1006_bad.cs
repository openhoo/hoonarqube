class Generator
{
    public virtual int Draw(int low = 1)
    {
        return low;
    }
}

class LoadedGenerator : Generator
{
    public override int Draw(int low = 6)
    {
        return low;
    }
}
