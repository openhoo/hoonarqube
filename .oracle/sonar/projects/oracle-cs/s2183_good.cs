public class Sample
{
    public int Shift(int value, int amount)
    {
        int small = value << 4;
        int symbolic = value >> amount;
        return small + symbolic;
    }
}
