public class Sample
{
    public int Fold(int value)
    {
        int first = value & -1;
        int second = value | 0;
        int third = value ^ 0;
        return first + second + third;
    }
}
