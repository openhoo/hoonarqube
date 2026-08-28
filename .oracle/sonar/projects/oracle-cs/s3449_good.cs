class Shifter
{
    int Shift(int page, int mask, int shift)
    {
        var a = page << 3;
        var b = mask >> shift;
        return a + b;
    }
}
