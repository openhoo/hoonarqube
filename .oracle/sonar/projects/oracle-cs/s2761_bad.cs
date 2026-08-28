public class Sample
{
    public int Check(int value, bool ready)
    {
        bool unchanged = !!ready;
        int same = ~~value;
        return unchanged ? same : 0;
    }
}
