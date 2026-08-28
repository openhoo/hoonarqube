[Flags]
enum Mask
{
    Read,
    Write
}

class Gate
{
    int Mix(Mask mask)
    {
        return (int)(mask & Mask.Read);
    }
}
