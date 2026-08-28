public class Sample
{
    public int Shift(int value)
    {
        int zeroShift = value << 0;
        int wideLeft = value << 32;
        int wideRight = value >> 40;
        return zeroShift + wideLeft + wideRight;
    }
}
