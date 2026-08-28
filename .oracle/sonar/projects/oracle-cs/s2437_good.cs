public class Sample
{
    public int Masked(int value, int mask)
    {
        int combined = value & mask;
        int flipped = value ^ 255;
        int widened = value | 128;
        return combined + flipped + widened;
    }
}
